<?php
abstract class BaseCheck {

    protected string $domain;

    // Hints optionale per scan (ex: ['login_url' => 'https://...'])
    protected array $hints = [];

    // Cookie jar per instanta — mentine sesiunea ca un browser real
    private string $cookieFile = '';

    // Contor cereri HTTP — pentru pauze automate
    private int $requestCount = 0;

    // User-Agents reale, rotite aleatoriu
    private const USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
    ];

    // Accept headers realiste
    private const ACCEPT_HEADERS = [
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    ];

    public function __construct(string $domain, array $hints = []) {
        $this->domain     = $domain;
        $this->hints      = $hints;
        $this->cookieFile = sys_get_temp_dir() . '/gpec_cookie_' . md5($domain) . '.txt';
    }

    // Returneaza un hint optional dupa cheie (ex: 'login_url')
    protected function getHint(string $key): ?string {
        $val = $this->hints[$key] ?? null;
        return ($val !== null && trim($val) !== '') ? trim($val) : null;
    }

    public function __destruct() {
        // Curata cookie jar la finalul verificarii
        if ($this->cookieFile && file_exists($this->cookieFile)) {
            @unlink($this->cookieFile);
        }
    }

    abstract public function run(): array;

    // ---- Pauza inteligenta intre cereri ----------------------------
    // GPEC_FAST_MODE=true => delay minimal (50-150ms) pentru scanare rapida

    protected function politeDelay(int $minMs = 400, int $maxMs = 1200): void {
        if (defined('GPEC_FAST_MODE') && GPEC_FAST_MODE) {
            usleep(random_int(50, 150) * 1000);
            return;
        }
        usleep(random_int($minMs, $maxMs) * 1000);
    }

    // ---- HTTP Helpers -----------------------------------------------

    protected function httpGet(string $url, int $timeout = 10, bool $followRedirects = true, int $retries = 2): array {
        $lastResult = ['httpCode' => 0, 'headers_raw' => '', 'body' => '', 'headers' => [], 'finalUrl' => $url];

        // Pauza intre cereri consecutive catre acelasi domeniu
        if ($this->requestCount > 0) {
            $this->politeDelay(300, 900);
        }
        $this->requestCount++;

        $ua     = self::USER_AGENTS[array_rand(self::USER_AGENTS)];
        $accept = self::ACCEPT_HEADERS[array_rand(self::ACCEPT_HEADERS)];

        for ($attempt = 0; $attempt <= $retries; $attempt++) {
            if ($attempt > 0) $this->politeDelay(800, 2000);

            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER  => true,
                CURLOPT_HEADER          => true,
                CURLOPT_FOLLOWLOCATION  => $followRedirects,
                CURLOPT_MAXREDIRS       => 5,
                CURLOPT_TIMEOUT         => $timeout,
                CURLOPT_CONNECTTIMEOUT  => 8,
                CURLOPT_SSL_VERIFYPEER  => false,
                CURLOPT_SSL_VERIFYHOST  => false,
                CURLOPT_USERAGENT       => $ua,
                CURLOPT_ENCODING        => 'gzip, deflate, br',
                CURLOPT_COOKIEFILE      => $this->cookieFile,
                CURLOPT_COOKIEJAR       => $this->cookieFile,
                CURLOPT_HTTPHEADER      => [
                    "Accept: {$accept}",
                    'Accept-Language: ro-RO,ro;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Accept-Encoding: gzip, deflate, br',
                    'Connection: keep-alive',
                    'Upgrade-Insecure-Requests: 1',
                    'Sec-Fetch-Dest: document',
                    'Sec-Fetch-Mode: navigate',
                    'Sec-Fetch-Site: none',
                    'Sec-Fetch-User: ?1',
                    'Cache-Control: max-age=0',
                ],
            ]);
            $response = curl_exec($ch);
            $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $headerSz = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            $curlErr  = curl_errno($ch);
            curl_close($ch);

            if ($response === false || $curlErr !== 0) continue;

            $headersRaw = substr($response, 0, $headerSz);
            $body       = substr($response, $headerSz);
            $headers    = $this->parseHeaders($headersRaw);
            $lastResult = compact('httpCode', 'headers', 'headersRaw', 'body', 'finalUrl');
            if ($httpCode > 0) break;
        }
        return $lastResult;
    }

    protected function httpPost(string $url, array $data, int $timeout = 10): array {
        // Pauza inainte de POST — mai ales pentru simulari brute force
        $this->politeDelay(600, 1500);
        $this->requestCount++;

        $ua = self::USER_AGENTS[array_rand(self::USER_AGENTS)];

        // Incearca sa obtina pagina mai intai (pentru cookies/token CSRF)
        $referer = preg_replace('#(https?://[^/]+).*#', '$1', $url);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_HEADER          => true,
            CURLOPT_POST            => true,
            CURLOPT_POSTFIELDS      => http_build_query($data),
            CURLOPT_FOLLOWLOCATION  => true,
            CURLOPT_MAXREDIRS       => 3,
            CURLOPT_TIMEOUT         => $timeout,
            CURLOPT_CONNECTTIMEOUT  => 8,
            CURLOPT_SSL_VERIFYPEER  => false,
            CURLOPT_USERAGENT       => $ua,
            CURLOPT_COOKIEFILE      => $this->cookieFile,
            CURLOPT_COOKIEJAR       => $this->cookieFile,
            CURLOPT_REFERER         => $referer,
            CURLOPT_HTTPHEADER      => [
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: ro-RO,ro;q=0.9,en-US;q=0.8,en;q=0.7',
                'Accept-Encoding: gzip, deflate, br',
                'Content-Type: application/x-www-form-urlencoded',
                'Connection: keep-alive',
                'Sec-Fetch-Dest: document',
                'Sec-Fetch-Mode: navigate',
                'Sec-Fetch-Site: same-origin',
                'Origin: ' . $referer,
            ],
        ]);
        $response = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSz = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        if ($response === false) return ['httpCode' => 0, 'body' => '', 'headers' => []];
        return [
            'httpCode' => $httpCode,
            'body'     => substr($response, $headerSz),
            'headers'  => $this->parseHeaders(substr($response, 0, $headerSz)),
        ];
    }

    protected function parseHeaders(string $raw): array {
        $headers = [];
        foreach (explode("\r\n", $raw) as $line) {
            if (str_contains($line, ':')) {
                [$key, $val] = explode(':', $line, 2);
                $headers[strtolower(trim($key))] = trim($val);
            }
        }
        return $headers;
    }

    // ---- TCP Port Test ----------------------------------------------

    protected function testPort(string $host, int $port, int $timeout = 3): bool {
        $fp = @stream_socket_client(
            "tcp://{$host}:{$port}",
            $errno, $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT
        );
        if ($fp !== false) {
            fclose($fp);
            return true;
        }
        // Fallback curl
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => "http://{$host}:{$port}",
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_NOBODY         => true,
        ]);
        curl_exec($ch);
        $errno2 = curl_errno($ch);
        curl_close($ch);
        return in_array($errno2, [0, 28, 56]);
    }

    // ---- DNS --------------------------------------------------------

    protected function resolveIP(string $domain): ?string {
        $records = @dns_get_record($domain, DNS_A);
        return $records[0]['ip'] ?? (gethostbyname($domain) !== $domain ? gethostbyname($domain) : null);
    }

    protected function getTxtRecords(string $host): array {
        $records = @dns_get_record($host, DNS_TXT);
        if (!$records) return [];
        return array_map(fn($r) => implode('', $r['entries'] ?? [$r['txt'] ?? '']), $records);
    }

    // ---- Result Builder ---------------------------------------------

    protected function result(
        string $gpecId, string $checkName,
        string $status, int $stars,
        string $summary, array $details, string $commentRo,
        array $rawData = []
    ): array {
        return [
            'gpec_id'         => $gpecId,
            'check_name'      => $checkName,
            'status'          => $status,
            'stars_suggested' => $stars,
            'summary'         => $summary,
            'details'         => $details,
            'comment_ro'      => $commentRo,
            'raw_data'        => $rawData,
        ];
    }
}
