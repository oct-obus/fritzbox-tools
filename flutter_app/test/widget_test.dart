import 'package:flutter_test/flutter_test.dart';
import 'package:fritz_tools/main.dart';

void main() {
  testWidgets('App renders', (WidgetTester tester) async {
    await tester.pumpWidget(const FritzToolsApp());
    expect(find.byType(FritzToolsApp), findsOneWidget);
  });
}
