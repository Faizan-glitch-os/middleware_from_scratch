
<?php

function requireAuth($client, $crntUserEmail): ?string
{
    if ($crntUserEmail !== null) {
        return $crntUserEmail;
    }

    $payload = json_encode(["error" => "authentication required"]);
    fwrite($client,
           "HTTP/1.1 401 Unauthorized\r\n" .
           "Content-Type: application/json\r\n" .
           "Content-Length: " . strlen($payload) . "\r\n" .
           "WWW-Authenticate: Session\r\n" .
           "Connection: close\r\n\r\n" .
           $payload
    );
    fclose($client);
    return null;
}

$users = [];
$data  = ["users" => ["Ali", "Ahmad"]];

$sessions = [];
$sessionTtl = 3600;

$host = "0.0.0.0";
$port = 8080;

$socket = stream_socket_server("tcp://$host:$port", $errno, $errstr);
if (!$socket) {
    echo "$errstr: $errno";
    exit(1);
}

while (true) {

    $client = @stream_socket_accept($socket, -1);
    if (!$client) {
        continue;
    }

    $request = '';
    while (($line = fgets($client)) !== false) {
        $request .= $line;
        if ($line === "\r\n" || $line === "\n") {
            break;
        }
    }
    if ($request === '') {
        fclose($client);
        continue;
    }

    [$header, $body] = array_pad(explode("\r\n\r\n", $request, 2), 2, '');
    $lines = explode("\r\n", trim($header));
    $requestLine = array_shift($lines);

    $headers = [];
    foreach ($lines as $h) {
        if (strpos($h, ':') === false) continue;
        [$k, $v] = explode(':', $h, 2);
        $headers[strtolower(trim($k))] = trim($v);
    }

    if (isset($headers['content-length'])) {
        $len = (int)$headers['content-length'];
        while (strlen($body) < $len) {
            $chunk = fread($client, $len - strlen($body));
            if ($chunk === false || $chunk === '') break;
            $body .= $chunk;
        }
    }

    $parts = explode(' ', $requestLine, 3);
    if (count($parts) < 3) {
        $payload = json_encode(["error" => "Malformed request"]);
        fwrite($client, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
        fclose($client);
        continue;
    }

    [$method, $uri, $protocol] = $parts;
    $method = strtoupper($method);
    $path   = parse_url($uri, PHP_URL_PATH) ?: '/';

    $sessionId = null;
    $crntUserEmail = null;

    if (isset($headers['cookie'])) {
        foreach (explode(';', $headers['cookie']) as $pair) {
            $pair = trim($pair);
            if (strpos($pair, '=') === false) continue;
            [$ck, $cv] = explode('=', $pair, 2);
            if (trim($ck) === 'session_id') {
                $sessionId = trim($cv);
            }
        }
    }

    if ($sessionId !== null && isset($sessions[$sessionId])) {
        $sess = $sessions[$sessionId];
        if (time() - $sess['created_at'] <= $sessionTtl) {
            $crntUserEmail = $sess['email'];
            $sessions[$sessionId]['last_seen'] = time();
        } else {
            unset($sessions[$sessionId]);
            $sessionId = null;
        }
    }

    if ($path === '/signup' && $method === 'POST') {
        $input = json_decode($body, true);

        if (!is_array($input) || !isset($input['email'], $input['password'])
            || !is_string($input['email']) || !is_string($input['password'])) {
            $payload = json_encode(["error" => "email and password required"]);
        fwrite($client, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
        fclose($client);
        continue;
            }

            $email    = strtolower(trim($input['email']));
            $password = $input['password'];

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $payload = json_encode(["error" => "invalid email"]);
                fwrite($client, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
                fclose($client);
                continue;
            }

            if (strlen($password) < 8) {
                $payload = json_encode(["error" => "password must be at least 8 characters"]);
                fwrite($client, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
                fclose($client);
                continue;
            }

            if (isset($users[$email])) {
                $payload = json_encode(["error" => "email already registered"]);
                fwrite($client, "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
                fclose($client);
                continue;
            }

            $users[$email] = [
                'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                'created_at'    => time(),
            ];

            $newSessionId = bin2hex(random_bytes(32));
            $sessions[$newSessionId] = [
                'email'      => $email,
                'created_at' => time(),
            ];

            $payload = json_encode(["message" => "account created", "email" => $email]);
            fwrite($client,
                   "HTTP/1.1 201 Created\r\n" .
                   "Content-Type: application/json\r\n" .
                   "Content-Length: " . strlen($payload) . "\r\n" .
                   "Set-Cookie: session_id=$newSessionId; HttpOnly; Path=/; Max-Age=$sessionTtl; SameSite=Lax\r\n" .
                   "Connection: close\r\n\r\n" .
                   $payload
            );
            fclose($client);
            continue;
    }

    if ($path === '/login' && $method === 'POST') {
        $input = json_decode($body, true);

        if (!is_array($input) || !isset($input['email'], $input['password'])
            || !is_string($input['email']) || !is_string($input['password'])) {
            $payload = json_encode(["error" => "email and password required"]);
        fwrite($client, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
        fclose($client);
        continue;
            }

            $email    = strtolower(trim($input['email']));
            $password = $input['password'];

            if (!isset($users[$email]) || !password_verify($password, $users[$email]['password_hash'])) {
                usleep(200000);
                $payload = json_encode(["error" => "invalid username or password"]);
                fwrite($client, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
                fclose($client);
                continue;
            }

            $newSessionId = bin2hex(random_bytes(32));
            $sessions[$newSessionId] = [
                'email'      => $email,
                'created_at' => time(),
            ];

            $payload = json_encode(["message" => "logged in", "email" => $email]);
            fwrite($client,
                   "HTTP/1.1 200 OK\r\n" .
                   "Content-Type: application/json\r\n" .
                   "Content-Length: " . strlen($payload) . "\r\n" .
                   "Set-Cookie: session_id=$newSessionId; HttpOnly; Path=/; Max-Age=$sessionTtl; SameSite=Lax\r\n" .
                   "Connection: close\r\n\r\n" .
                   $payload
            );
            fclose($client);
            continue;
    }

    if ($path === '/logout' && $method === 'POST') {
        if ($sessionId !== null && isset($sessions[$sessionId])) {
            unset($sessions[$sessionId]);
        }
        $payload = json_encode(["message" => "logged out"]);
        fwrite($client,
               "HTTP/1.1 200 OK\r\n" .
               "Content-Type: application/json\r\n" .
               "Content-Length: " . strlen($payload) . "\r\n" .
               "Set-Cookie: session_id=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax\r\n" .
               "Connection: close\r\n\r\n" .
               $payload
        );
        fclose($client);
        continue;
    }

    if (($path === '/' || $path === '/users') && $method === 'GET') {
        $payload = json_encode($data);
        fwrite($client, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
        fclose($client);
        continue;
    }

    if ($path === '/users' && $method === 'POST') {
        if (requireAuth($client, $crntUserEmail) === null) {
            continue;
        }

        $input = json_decode($body, true);
        if (!is_array($input) || !array_key_exists('user', $input)) {
            $payload = json_encode(["error" => "user field required"]);
            fwrite($client, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
            fclose($client);
            continue;
        }
        if (!is_string($input['user']) || trim($input['user']) === '') {
            $payload = json_encode(["error" => "user should be a string"]);
            fwrite($client, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
            fclose($client);
            continue;
        }

        $data['users'][] = $input['user'];
        $payload = json_encode($data);
        fwrite($client, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
        fclose($client);
        continue;
    }

    if ($path === '/users' && $method === 'DELETE') {
        if (requireAuth($client, $crntUserEmail) === null) {
            continue;
        }

        if (empty($data['users'])) {
            $payload = json_encode(["error" => "no users to delete"]);
            fwrite($client, "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
            fclose($client);
            continue;
        }

        array_pop($data['users']);
        fwrite($client, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        fclose($client);
        continue;
    }


    $payload = json_encode(["error" => "Not found"]);
    fwrite($client, "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\nConnection: close\r\n\r\n" . $payload);
    fclose($client);
}

