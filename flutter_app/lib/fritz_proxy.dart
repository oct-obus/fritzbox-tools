import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:shelf/shelf.dart' as shelf;
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_router/shelf_router.dart';
import 'package:http/http.dart' as http;
import 'package:flutter/services.dart' show rootBundle;
import 'package:crypto/crypto.dart' show Hmac, sha256;
import 'package:network_info_plus/network_info_plus.dart';

/// Local HTTP server that serves the web UI and proxies Fritz!Box API calls.
class FritzProxy {
  HttpServer? _server;
  static const int _fixedPort = 8742;
  int _port = 0;

  int get port => _port;
  String get url => 'http://127.0.0.1:$_port';

  Future<void> start() async {
    final router = Router();

    // Serve the HTML UI
    router.get('/', (shelf.Request request) async {
      final html = await rootBundle.loadString('assets/fritzbox_tools.html');
      return shelf.Response.ok(html,
          headers: {'Content-Type': 'text/html; charset=utf-8'});
    });

    // Return the device's local network IPs (for "you are here" feature)
    router.get('/local-ip', (shelf.Request request) async {
      try {
        final interfaces = await NetworkInterface.list(
          type: InternetAddressType.IPv4,
        );
        final ips = <String>[];
        for (final iface in interfaces) {
          for (final addr in iface.addresses) {
            if (!addr.isLoopback) {
              ips.add(addr.address);
            }
          }
        }
        return _jsonResponse({'ips': ips});
      } catch (e) {
        return _jsonResponse({'error': 'Failed to get local IPs: $e'});
      }
    });

    // Return the device's current WiFi BSSID (for AP detection)
    router.get('/wifi-bssid', (shelf.Request request) async {
      try {
        final info = NetworkInfo();
        final bssid = await info.getWifiBSSID();
        return _jsonResponse({'bssid': bssid});
      } catch (e) {
        return _jsonResponse({'bssid': null, 'error': e.toString()});
      }
    });

    // Login endpoint: handles PBKDF2 auth
    router.post('/proxy/<host>/login', (shelf.Request request, String host) async {
      host = Uri.decodeComponent(host);
      try {
        final body = json.decode(await request.readAsString());
        final username = body['username'] ?? '';
        final password = body['password'] ?? '';

        // Get challenge
        final challengeResp = await http.get(
          Uri.parse('http://$host/login_sid.lua?version=2'),
          headers: {'Accept': 'application/json'},
        );
        final challengeData = json.decode(challengeResp.body);
        final si = challengeData['sessionInfo'] ?? challengeData;
        final challenge = si['challenge'] ?? si['Challenge'] ?? '';
        final currentSid = si['sid'] ?? si['SID'] ?? '';

        if (currentSid != '0000000000000000') {
          return _jsonResponse({'sid': currentSid});
        }

        final blockTime = si['blockTime'] ?? si['BlockTime'] ?? 0;
        if (blockTime is int && blockTime > 0) {
          return _jsonResponse({'error': 'Login blocked for ${blockTime}s'});
        }

        // Solve challenge
        String response;
        if (challenge.contains('\$')) {
          response = await _solveChallengeV2(challenge, password);
        } else {
          response = _solveChallengeV1(challenge, password);
        }

        // Login
        final loginResp = await http.post(
          Uri.parse('http://$host/login_sid.lua?version=2'),
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'username=${Uri.encodeComponent(username)}&response=${Uri.encodeComponent(response)}',
        );
        final loginData = json.decode(loginResp.body);
        final loginSi = loginData['sessionInfo'] ?? loginData;
        final sid = loginSi['sid'] ?? loginSi['SID'] ?? '';

        if (sid == '0000000000000000') {
          final bt = loginSi['blockTime'] ?? 0;
          return _jsonResponse({'error': 'Login failed${bt > 0 ? " (blocked ${bt}s)" : ""}'});
        }

        return _jsonResponse({'sid': sid});
      } catch (e) {
        return _jsonResponse({'error': 'Login failed: $e'});
      }
    });

    // API GET proxy
    router.get('/proxy/<host>/api/<endpoint|.*>', (shelf.Request request, String host, String endpoint) async {
      host = Uri.decodeComponent(host);
      final sid = request.url.queryParameters['sid'] ?? '';
      try {
        final resp = await http.get(
          Uri.parse('http://$host/api/v0/generic/$endpoint'),
          headers: {
            'AUTHORIZATION': 'AVM-SID $sid',
            'Accept': 'application/json',
          },
        );
        return shelf.Response.ok(resp.body,
            headers: {'Content-Type': 'application/json'});
      } catch (e) {
        return _jsonResponse({'error': 'API call failed: $e'});
      }
    });

    // data.lua proxy (for mesh topology, etc.)
    router.get('/proxy/<host>/data/<page>', (shelf.Request request, String host, String page) async {
      host = Uri.decodeComponent(host);
      final sid = request.url.queryParameters['sid'] ?? '';
      try {
        final resp = await http.post(
          Uri.parse('http://$host/data.lua'),
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
          },
          body: 'sid=${Uri.encodeComponent(sid)}&page=${Uri.encodeComponent(page)}',
        );
        return shelf.Response.ok(resp.body,
            headers: {'Content-Type': 'application/json'});
      } catch (e) {
        return _jsonResponse({'error': 'data.lua call failed: $e'});
      }
    });

    // Mesh start
    router.post('/proxy/<host>/mesh/start', (shelf.Request request, String host) async {
      host = Uri.decodeComponent(host);
      try {
        final body = json.decode(await request.readAsString());
        final sid = body['sid'] ?? '';
        final repeaterIp = body['repeater_ip'];
        final repeaterPw = body['repeater_password'] ?? '';

        // Start mesh coupling on master
        await http.put(
          Uri.parse('http://$host/api/v0/generic/nexus'),
          headers: {
            'AUTHORIZATION': 'AVM-SID $sid',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          },
          body: json.encode({'enhanced_trust_mode': '1'}),
        );

        final result = <String, dynamic>{
          'message': 'Mesh coupling started.',
        };

        // Get initial peers
        try {
          final nexusResp = await http.get(
            Uri.parse('http://$host/api/v0/generic/nexus'),
            headers: {
              'AUTHORIZATION': 'AVM-SID $sid',
              'Accept': 'application/json',
            },
          );
          final nexus = json.decode(nexusResp.body);
          result['initial_peers'] = _extractTrustedPeers(nexus);
        } catch (_) {}

        // Trigger WPS on repeater via TR-064
        if (repeaterIp != null && repeaterIp.toString().isNotEmpty) {
          try {
            final wpsResult = await _triggerWps(repeaterIp, repeaterPw);
            result['wps_message'] = wpsResult;
          } catch (e) {
            result['wps_message'] = 'WPS trigger failed: $e. Press button manually.';
          }
        }

        return _jsonResponse(result);
      } catch (e) {
        return _jsonResponse({'error': 'Mesh start failed: $e'});
      }
    });

    // Mesh poll
    router.get('/proxy/<host>/mesh/poll', (shelf.Request request, String host) async {
      host = Uri.decodeComponent(host);
      final sid = request.url.queryParameters['sid'] ?? '';
      try {
        final resp = await http.get(
          Uri.parse('http://$host/api/v0/generic/nexus'),
          headers: {
            'AUTHORIZATION': 'AVM-SID $sid',
            'Accept': 'application/json',
          },
        );
        final nexus = json.decode(resp.body);
        final peers = _extractTrustedPeers(nexus);
        return _jsonResponse({
          'peer_count': peers.length,
          'new_peers': peers,
        });
      } catch (e) {
        return _jsonResponse({'error': 'Poll failed: $e'});
      }
    });

    // Use fixed port so WebView localStorage persists across launches
    _port = _fixedPort;

    final handler = const shelf.Pipeline()
        .addMiddleware(shelf.logRequests())
        .addHandler(router.call);

    _server = await shelf_io.serve(handler, '127.0.0.1', _port);
  }

  Future<void> stop() async {
    await _server?.close();
  }

  shelf.Response _jsonResponse(Map<String, dynamic> data) {
    return shelf.Response.ok(
      json.encode(data),
      headers: {'Content-Type': 'application/json'},
    );
  }

  List<String> _extractTrustedPeers(Map<String, dynamic> nexus) {
    final peers = <String>[];
    final peersData = nexus['peers'];
    if (peersData is List && peersData.isNotEmpty) {
      final first = peersData[0];
      if (first is Map && first['peer'] is List) {
        for (final peer in first['peer']) {
          if (peer is Map &&
              peer['peer_trusted'] == '1' &&
              peer['iam_trusted'] == '1' &&
              peer['UID'] != null) {
            peers.add(peer['UID'].toString());
          }
        }
      }
    }
    return peers;
  }

  /// PBKDF2 v2 challenge solver
  Future<String> _solveChallengeV2(String challenge, String password) async {
    final parts = challenge.split('\$');
    final iter1 = int.parse(parts[1]);
    final salt1 = _hexToBytes(parts[2]);
    final iter2 = int.parse(parts[3]);
    final salt2 = _hexToBytes(parts[4]);

    final key1 = _pbkdf2(utf8.encode(password), salt1, iter1, 32);
    final key2 = _pbkdf2(key1, salt2, iter2, 32);
    return '${_bytesToHex(salt2)}\$${_bytesToHex(key2)}';
  }

  /// Legacy MD5 challenge solver
  String _solveChallengeV1(String challenge, String password) {
    final str = '$challenge-$password';
    // UTF-16LE encoding
    final bytes = <int>[];
    for (var i = 0; i < str.length; i++) {
      final c = str.codeUnitAt(i);
      bytes.add(c & 0xff);
      bytes.add((c >> 8) & 0xff);
    }
    final hash = md5Digest(bytes);
    return '$challenge-$hash';
  }

  /// PBKDF2-HMAC-SHA256
  List<int> _pbkdf2(List<int> password, List<int> salt, int iterations, int dkLen) {
    final hmac = Hmac(sha256, password);
    final numBlocks = (dkLen + 31) ~/ 32;
    final dk = <int>[];

    for (var block = 1; block <= numBlocks; block++) {
      final blockBytes = [
        (block >> 24) & 0xff,
        (block >> 16) & 0xff,
        (block >> 8) & 0xff,
        block & 0xff,
      ];
      var u = hmac.convert([...salt, ...blockBytes]).bytes;
      var result = List<int>.from(u);

      for (var i = 1; i < iterations; i++) {
        u = hmac.convert(u).bytes;
        for (var j = 0; j < result.length; j++) {
          result[j] ^= u[j];
        }
      }
      dk.addAll(result);
    }
    return dk.sublist(0, dkLen);
  }

  List<int> _hexToBytes(String hex) {
    final bytes = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return bytes;
  }

  String _bytesToHex(List<int> bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  Future<String> _triggerWps(String repeaterIp, String password) async {
    const service = 'urn:dslforum-org:service:WLANConfiguration:1';
    const controlUrl = '/upnp/control/wlanconfig1';

    final soapBody = '''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:X_AVM-DE_SetWPSConfig xmlns:u="$service">
      <NewX_AVM-DE_WPSMode>pbc</NewX_AVM-DE_WPSMode>
    </u:X_AVM-DE_SetWPSConfig>
  </s:Body>
</s:Envelope>''';

    // First attempt without auth
    try {
      final resp = await http.post(
        Uri.parse('http://$repeaterIp:49000$controlUrl'),
        headers: {
          'Content-Type': 'text/xml; charset=utf-8',
          'SOAPAction': '"$service#X_AVM-DE_SetWPSConfig"',
        },
        body: soapBody,
      );

      if (resp.statusCode == 401 && password.isNotEmpty) {
        // Need HTTP Digest auth — use dart:io HttpClient for digest support
        final client = HttpClient();
        try {
          client.addCredentials(
            Uri.parse('http://$repeaterIp:49000$controlUrl'),
            'HTTPS Access',
            HttpClientDigestCredentials('', password),
          );
          final req = await client.postUrl(Uri.parse('http://$repeaterIp:49000$controlUrl'));
          req.headers.contentType = ContentType('text', 'xml', charset: 'utf-8');
          req.headers.set('SOAPAction', '"$service#X_AVM-DE_SetWPSConfig"');
          req.write(soapBody);
          final digestResp = await req.close();
          await digestResp.transform(utf8.decoder).join();
          return 'WPS triggered on $repeaterIp (digest auth).';
        } finally {
          client.close();
        }
      }

      return 'WPS triggered on $repeaterIp.';
    } catch (e) {
      return 'WPS trigger failed: $e';
    }
  }
}

/// Minimal MD5 implementation for legacy Fritz!Box auth
String md5Digest(List<int> input) {
  int a0 = 0x67452301;
  int b0 = 0xEFCDAB89;
  int c0 = 0x98BADCFE;
  int d0 = 0x10325476;

  final s = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];

  final k = <int>[
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
  ];

  // Padding
  final originalLen = input.length;
  final msg = List<int>.from(input);
  msg.add(0x80);
  while (msg.length % 64 != 56) {
    msg.add(0);
  }
  final bitLen = originalLen * 8;
  for (var i = 0; i < 8; i++) {
    msg.add((bitLen >> (i * 8)) & 0xff);
  }

  // Process 512-bit chunks
  for (var offset = 0; offset < msg.length; offset += 64) {
    final m = List<int>.filled(16, 0);
    for (var i = 0; i < 16; i++) {
      m[i] = msg[offset + i * 4] |
          (msg[offset + i * 4 + 1] << 8) |
          (msg[offset + i * 4 + 2] << 16) |
          (msg[offset + i * 4 + 3] << 24);
    }

    var a = a0, b = b0, c = c0, d = d0;

    for (var i = 0; i < 64; i++) {
      int f, g;
      if (i < 16) {
        f = (b & c) | ((~b) & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | ((~d) & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | (~d));
        g = (7 * i) % 16;
      }
      f = (f + a + k[i] + m[g]) & 0xFFFFFFFF;
      a = d;
      d = c;
      c = b;
      b = (b + _leftRotate(f, s[i])) & 0xFFFFFFFF;
    }

    a0 = (a0 + a) & 0xFFFFFFFF;
    b0 = (b0 + b) & 0xFFFFFFFF;
    c0 = (c0 + c) & 0xFFFFFFFF;
    d0 = (d0 + d) & 0xFFFFFFFF;
  }

  String toHex(int v) {
    var result = '';
    for (var i = 0; i < 4; i++) {
      result += ((v >> (i * 8)) & 0xff).toRadixString(16).padLeft(2, '0');
    }
    return result;
  }

  return '${toHex(a0)}${toHex(b0)}${toHex(c0)}${toHex(d0)}';
}

int _leftRotate(int x, int c) {
  return ((x << c) | ((x & 0xFFFFFFFF) >> (32 - c))) & 0xFFFFFFFF;
}
