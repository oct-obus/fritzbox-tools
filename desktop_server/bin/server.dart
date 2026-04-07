import 'dart:io';
import '../lib/fritz_proxy.dart';

void main(List<String> args) async {
  final port = args.isNotEmpty ? int.tryParse(args[0]) ?? 8742 : 8742;
  final proxy = FritzProxy(port: port);
  await proxy.start();
  print('Fritz!Box Tools running at http://localhost:$port/');
  print('Open this URL in your browser.');
  print('Press Ctrl+C to stop.');

  // Handle Ctrl+C gracefully
  ProcessSignal.sigint.watch().listen((_) async {
    print('\nShutting down...');
    await proxy.stop();
    exit(0);
  });
}
