import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'fritz_proxy.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const FritzToolsApp());
}

class FritzToolsApp extends StatelessWidget {
  const FritzToolsApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Fritz!Box Tools',
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF0D1117),
      ),
      home: const FritzToolsScreen(),
      debugShowCheckedModeBanner: false,
    );
  }
}

class FritzToolsScreen extends StatefulWidget {
  const FritzToolsScreen({super.key});

  @override
  State<FritzToolsScreen> createState() => _FritzToolsScreenState();
}

class _FritzToolsScreenState extends State<FritzToolsScreen> {
  final FritzProxy _proxy = FritzProxy();
  WebViewController? _controller;
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _startProxy();
  }

  Future<void> _startProxy() async {
    try {
      await _proxy.start();
      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..setBackgroundColor(const Color(0xFF0D1117))
        ..setNavigationDelegate(NavigationDelegate(
          onPageFinished: (_) {
            setState(() => _loading = false);
          },
          onWebResourceError: (error) {
            setState(() => _error = error.description);
          },
        ))
        ..loadRequest(Uri.parse(_proxy.url));

      setState(() {
        _controller = controller;
      });
    } catch (e) {
      setState(() {
        _error = 'Failed to start proxy: $e';
        _loading = false;
      });
    }
  }

  @override
  void dispose() {
    _proxy.stop();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_error != null) {
      return Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Text(
              _error!,
              style: const TextStyle(color: Colors.red),
              textAlign: TextAlign.center,
            ),
          ),
        ),
      );
    }

    if (_controller == null) {
      return const Scaffold(
        body: Center(
          child: CircularProgressIndicator(),
        ),
      );
    }

    return Scaffold(
      body: SafeArea(
        child: Stack(
          children: [
            WebViewWidget(controller: _controller!),
            if (_loading)
              const Center(child: CircularProgressIndicator()),
          ],
        ),
      ),
    );
  }
}
