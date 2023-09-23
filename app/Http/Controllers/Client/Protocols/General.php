<?php

namespace App\Http\Controllers\Client\Protocols;


use App\Utils\Helper;

class General
{
    public $flag = 'general';
    private $servers;
    private $user;

    public function __construct($user, $servers)
    {
        $this->user = $user;
        $this->servers = $servers;
    }

    public function handle()
    {
        $servers = $this->servers;
        $user = $this->user;
        $uri = '';

        foreach ($servers as $item) {
            if ($item['type'] === 'vmess') {
                if (is_array($item['tags']) && in_array("VLESS", $item['tags'])) {
                    $uri .= self::buildVless($user['uuid'], $item);
                } else {
                    $uri .= self::buildVmess($user['uuid'], $item);
	        }
            }
            if ($item['type'] === 'shadowsocks') {
                $uri .= self::buildShadowsocks($user['uuid'], $item);
            }
            if ($item['type'] === 'trojan') {
                $uri .= self::buildTrojan($user['uuid'], $item);
            }
            if ($item['type'] === 'hysteria') {
                $uri .= self::buildHysteria($user['uuid'], $item);
            }
        }
        return base64_encode($uri);
    }

    public static function buildShadowsocks($password, $server)
    {
        if ($server['cipher'] === '2022-blake3-aes-128-gcm') {
            $serverKey = Helper::getServerKey($server['created_at'], 16);
            $userKey = Helper::uuidToBase64($password, 16);
            $password = "{$serverKey}:{$userKey}";
        }
        if ($server['cipher'] === '2022-blake3-aes-256-gcm') {
            $serverKey = Helper::getServerKey($server['created_at'], 32);
            $userKey = Helper::uuidToBase64($password, 32);
            $password = "{$serverKey}:{$userKey}";
        }
        $name = rawurlencode($server['name']);
        $str = str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode("{$server['cipher']}:{$password}")
        );
        $remote = filter_var($server['host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '[' . $server['host'] . ']' : $server['host'];
        if ($server['obfs']) {
            if ($server['obfs_settings']['host']) {
                return "ss://{$str}@{$remote}:{$server['port']}/?plugin=obfs-local;obfs=http;obfs-host={$server['obfs_settings']['host']}#{$name}\r\n";
            } else {
                return "ss://{$str}@{$remote}:{$server['port']}/?plugin=obfs-local;obfs=http#{$name}\r\n";
            }
        } else {
            return "ss://{$str}@{$remote}:{$server['port']}#{$name}\r\n";
        }
    }

    public static function buildVmess($uuid, $server)
    {
        $config = [
            "v" => "2",
            "ps" => $server['name'],
            "add" => $server['host'],
            "port" => (string)$server['port'],
            "id" => $uuid,
            "aid" => '0',
            "net" => $server['network'],
            "type" => "none",
            "host" => "",
            "path" => "",
            "tls" => $server['tls'] ? "tls" : "",
        ];
        if ($server['tls']) {
            $config['fp'] = 'firefox';
            $config['scy'] = 'zero';
            if ($server['tlsSettings']) {
                $tlsSettings = $server['tlsSettings'];
                if (isset($tlsSettings['serverName']) && !empty($tlsSettings['serverName']))
                    $config['sni'] = $tlsSettings['serverName'];
            }
        }
        if ((string)$server['network'] === 'tcp') {
            $tcpSettings = $server['networkSettings'];
            if (isset($tcpSettings['header']['type'])) $config['type'] = $tcpSettings['header']['type'];
            if (isset($tcpSettings['header']['request']['path'][0])) $config['path'] = $tcpSettings['header']['request']['path'][0];
            if (isset($tcpSettings['header']['headers']['Host'][0])) $config['host'] = $tcpSettings['header']['headers']['Host'][0];
        }
        if ((string)$server['network'] === 'ws') {
            $wsSettings = $server['networkSettings'];
            if (isset($wsSettings['path'])) $config['path'] = "${wsSettings['path']}?ed=2048";
            if (isset($wsSettings['headers']['Host'])) $config['host'] = $wsSettings['headers']['Host'];
        }
        if ((string)$server['network'] === 'grpc') {
            $grpcSettings = $server['networkSettings'];
            if (isset($grpcSettings['serviceName'])) $config['path'] = $grpcSettings['serviceName'];
        }
        return "vmess://" . base64_encode(json_encode($config)) . "\r\n";
    }

    public static function buildTrojan($password, $server)
    {
        $remote = filter_var($server['host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '[' . $server['host'] . ']' : $server['host'];
        $name = rawurlencode($server['name']);
        $query = http_build_query([
            'allowInsecure' => $server['allow_insecure'],
            'peer' => $server['server_name'],
            'sni' => $server['server_name'],
            'fp' => 'firefox'
        ]);
        $uri = "trojan://{$password}@{$remote}:{$server['port']}?{$query}#{$name}";
        $uri .= "\r\n";
        return $uri;
    }

    public static function buildHysteria($password, $server)
    {
        $remote = filter_var($server['host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '[' . $server['host'] . ']' : $server['host'];
     	$name = rawurlencode($server['name']);
        if (is_array($server['tags']) && in_array("hy2", $server['tags'])) {
            $query2 = http_build_query([
                'insecure' => $server['insecure'],
                'sni' => $server['server_name']
//                'obfs' => 'salamander',
//                'obfs-password' => $server['server_key']
            ]);
            $uri = "hysteria2://{$password}@{$remote}:{$server['port']}/?{$query2}#{$name}";
        } else {
            $query = http_build_query([
                'protocol' => 'udp',
                'auth' => $password,
                'insecure' => $server['insecure'],
                'peer' => $server['server_name'],
                'upmbps' => $server['up_mbps'],
                'downmbps' => $server['up_mbps']
    //            'obfsParam' => $server['server_key']
            ]);
            $uri = "hysteria://{$remote}:{$server['port']}?{$query}#{$name}";
        }
        $uri .= "\r\n";
        return $uri;
    }
    public static function buildVless($uuid, $server)
    {
        $name = rawurlencode($server['name']);
        $config = [];
        $config['type'] = $server['network'];
        $config['encryption'] = 'none';
        $config['security'] = $server['tls'] ? "tls" : "none";
        if ($server['tls']) {
            $config['fp'] = 'firefox';
            if (is_array($server['tags']) && in_array("VLESS", $server['tags']) && in_array("XTLS", $server['tags'])) {
                    $config['flow'] = "xtls-rprx-vision";
            }
            if ($server['tlsSettings']) {
                $tlsSettings = $server['tlsSettings'];
                if (isset($tlsSettings['serverName']) && !empty($tlsSettings['serverName']))
                    $config['sni'] = $tlsSettings['serverName'];
            }
        }
        if ((string)$server['network'] === 'tcp') {
            $tcpSettings = $server['networkSettings'];
            if (isset($tcpSettings['header']['type'])) $config['type'] = $tcpSettings['header']['type'];
            if (isset($tcpSettings['header']['request']['path'][0])) $config['path'] = $tcpSettings['header']['request']['path'][0];
            if (isset($tcpSettings['header']['headers']['Host'][0])) $config['host'] = $tcpSettings['header']['headers']['Host'][0];
        }
        if ((string)$server['network'] === 'ws') {
            $wsSettings = $server['networkSettings'];
            if (isset($wsSettings['path'])) $config['path'] = "${wsSettings['path']}?ed=2048";
            if (isset($wsSettings['headers']['Host'])) $config['host'] = $wsSettings['headers']['Host'];
        }
        if ((string)$server['network'] === 'grpc') {
            $grpcSettings = $server['networkSettings'];
            if (isset($grpcSettings['serviceName'])) $config['serviceName'] = $grpcSettings['serviceName'];
            $config['mode'] = 'multi';
        }
        $query = http_build_query($config);
        $remote = filter_var($server['host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '[' . $server['host'] . ']' : $server['host'];
        $uri = "vless://{$uuid}@{$remote}:{$server['port']}?{$query}#{$name}";
        $uri .= "\r\n";
        return $uri;
    }
}
