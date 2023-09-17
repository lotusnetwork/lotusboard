<?php

namespace App\Http\Controllers\Client\Protocols;

use App\Utils\Helper;

class SF
{
    public $flag = 'sf';
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
        $defaultConfig = base_path() . '/resources/rules/default.sb.json';
        $customConfig = base_path() . '/resources/rules/custom.sb.json';
        if (\File::exists($customConfig)) {
            $config = json_decode(file_get_contents($customConfig), true);
        } else {
            $config = json_decode(file_get_contents($defaultConfig), true);
        }
        if (!isset($config['outbounds']) || !is_array($config['outbounds'])) {
            $config['outbounds'] = [];
        }
        foreach ($servers as $item) {
            if ($item['type'] === 'shadowsocks') {
                array_push($config['outbounds'], self::buildShadowsocks($user['uuid'], $item));
            }
            if ($item['type'] === 'vmess') {
                if (is_array($item['tags']) && in_array("VLESS", $item['tags'])) {
                    array_push($config['outbounds'], self::buildVless($user['uuid'], $item));
                } else {
                    array_push($config['outbounds'], self::buildVmess($user['uuid'], $item));
	        }
            }
            if ($item['type'] === 'trojan') {
                array_push($config['outbounds'], self::buildTrojan($user['uuid'], $item));
            }
            if ($item['type'] === 'hysteria') {
                array_push($config['outbounds'], self::buildHysteria($user['uuid'], $item));
            }
        }
        $config = json_encode($config);
        return $config;
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
        $array = [];
        $array['tag'] = $server['name'];
        $array['type'] = 'ss';
        $array['server'] = $server['host'];
        $array['server_port'] = $server['port'];
        $array['method'] = $server['cipher'];
        $array['password'] = $password;
        return $array;
    }

    public static function buildVmess($uuid, $server)
    {
        $array = [];
        $array['tag'] = $server['name'];
        $array['type'] = 'vmess';
        $array['server'] = $server['host'];
        $array['server_port'] = $server['port'];
        $array['uuid'] = $uuid;
        $array['alter_id'] = 0;
        $array['security'] = 'auto';

        if ($server['tls']) {
            $array['tls']['enabled'] = true;
            $array['tls']['utls']['enabled'] = true;
            $array['tls']['utls']['fingerprint'] = 'firefox';
            $array['security'] = 'zero';
            if ($server['tlsSettings']) {
                $tlsSettings = $server['tlsSettings'];
                if (isset($tlsSettings['allowInsecure']) && !empty($tlsSettings['allowInsecure']))
                    $array['tls']['insecure'] = ($tlsSettings['allowInsecure'] ? true : false);
                if (isset($tlsSettings['serverName']) && !empty($tlsSettings['serverName']))
                    $array['tls']['server_name'] = $tlsSettings['serverName'];
            }
        }
        if ($server['network'] === 'ws') {
            $array['transport'] = [];
            $array['transport']['type'] = 'ws';
            if ($server['networkSettings']) {
                $wsSettings = $server['networkSettings'];
                if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                    $array['transport']['path'] = $wsSettings['path'];
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                    $array['transport']['headers'] = ['Host' => $wsSettings['headers']['Host']];
            }
            $array['transport']['max_early_data'] = 2048;
            $array['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol';
        }
        if ($server['network'] === 'grpc') {
            $array['transport'] = [];
            $array['transport']['type'] = 'grpc';
            if ($server['networkSettings']) {
                $grpcSettings = $server['networkSettings'];
                if (isset($grpcSettings['serviceName'])) $array['transport']['service_name'] = $grpcSettings['serviceName'];
            }
        }

        return $array;
    }

    public static function buildTrojan($password, $server)
    {
        $array = [];
        $array['tag'] = $server['name'];
        $array['type'] = 'trojan';
        $array['server'] = $server['host'];
        $array['server_port'] = $server['port'];
        $array['password'] = $password;
        $array['tls']['enabled'] = true;
        $array['tls']['utls']['enabled'] = true;
        $array['tls']['utls']['fingerprint'] = 'firefox';
        if (!empty($server['server_name'])) $array['tls']['server_name'] = $server['server_name'];
        if (!empty($server['allow_insecure'])) $array['tls']['insecure'] = ($server['allow_insecure'] ? true : false);
        return $array;
    }

    public static function buildHysteria($password, $server)
    {
     	$array = [];
        $array['tag'] = $server['name'];
        $array['type'] = 'hysteria';
        $array['server'] = $server['host'];
        $array['server_port'] = $server['port'];
        $array['auth_str'] = $password;
//        $array['obfs'] = $server['server_key'];
        $array['up_mbps'] = $server['up_mbps'];
        $array['down_mbps'] = $server['down_mbps'];
        if (!empty($server['server_name'])) $array['tls']['server_name'] = $server['server_name'];
        $array['tls']['insecure'] = !empty($server['insecure']) ? true : false;
        return $array;
    }

    public static function buildVless($uuid, $server)
    {
        $array = [];
        $array['tag'] = $server['name'];
        $array['type'] = 'vmess';
        $array['server'] = $server['host'];
        $array['server_port'] = $server['port'];
        $array['uuid'] = $uuid;

        if ($server['tls']) {
            if (is_array($server['tags']) && in_array("VLESS", $server['tags']) && in_array("XTLS", $server['tags'])) {
                $array['flow'] = "xtls-rprx-vision";
            }
            $array['tls']['enabled'] = true;
            $array['tls']['utls']['enabled'] = true;
            $array['tls']['utls']['fingerprint'] = 'firefox';
            if ($server['tlsSettings']) {
                $tlsSettings = $server['tlsSettings'];
                if (isset($tlsSettings['allowInsecure']) && !empty($tlsSettings['allowInsecure']))
                    $array['tls']['insecure'] = ($tlsSettings['allowInsecure'] ? true : false);
                if (isset($tlsSettings['serverName']) && !empty($tlsSettings['serverName']))
                    $array['tls']['server_name'] = $tlsSettings['serverName'];
            }
        }
        if ($server['network'] === 'ws') {
            $array['transport'] = [];
            $array['transport']['type'] = 'ws';
            if ($server['networkSettings']) {
                $wsSettings = $server['networkSettings'];
                if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                    $array['transport']['path'] = $wsSettings['path'];
                if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                    $array['transport']['headers'] = ['Host' => $wsSettings['headers']['Host']];
            }
            $array['transport']['max_early_data'] = 2048;
            $array['transport']['early_data_header_name'] = 'Sec-WebSocket-Protocol';
        }
        if ($server['network'] === 'grpc') {
            $array['transport'] = [];
            $array['transport']['type'] = 'grpc';
            if ($server['networkSettings']) {
                $grpcSettings = $server['networkSettings'];
                if (isset($grpcSettings['serviceName'])) $array['transport']['service_name'] = $grpcSettings['serviceName'];
            }
        }

        return $array;
    }
}
