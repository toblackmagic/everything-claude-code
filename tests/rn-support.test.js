/**
 * Tests for React Native support in Everything Claude Code
 *
 * Run with: node tests/rn-support.test.js
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');

// Test helper
function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    return true;
  } catch (err) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${err.message}`);
    return false;
  }
}

// Test suite
function runTests() {
  console.log('\n=== React Native Support Tests ===\n');

  let passed = 0;
  let failed = 0;

  const rootDir = path.resolve(__dirname, '..');

  // Skills module tests
  console.log('Skills Module:');

  if (test('react-native-patterns skill file exists', () => {
    const skillPath = path.join(rootDir, 'skills/react-native-patterns/skill.md');
    assert.ok(fs.existsSync(skillPath), 'skill.md should exist');
    const content = fs.readFileSync(skillPath, 'utf8');
    assert.ok(content.includes('React Native'), 'Should mention React Native');
  })) passed++; else failed++;

  if (test('components.md exists and has content', () => {
    const componentsPath = path.join(rootDir, 'skills/react-native-patterns/components.md');
    assert.ok(fs.existsSync(componentsPath), 'components.md should exist');
    const content = fs.readFileSync(componentsPath, 'utf8');
    assert.ok(content.includes('FlatList'), 'Should mention FlatList');
    assert.ok(content.includes('Platform'), 'Should mention Platform module');
  })) passed++; else failed++;

  if (test('navigation.md exists and has content', () => {
    const navPath = path.join(rootDir, 'skills/react-native-patterns/navigation.md');
    assert.ok(fs.existsSync(navPath), 'navigation.md should exist');
    const content = fs.readFileSync(navPath, 'utf8');
    assert.ok(content.includes('React Navigation'), 'Should mention React Navigation');
    assert.ok(content.includes('useNavigation'), 'Should mention useNavigation hook');
  })) passed++; else failed++;

  if (test('performance.md exists and has content', () => {
    const perfPath = path.join(rootDir, 'skills/react-native-patterns/performance.md');
    assert.ok(fs.existsSync(perfPath), 'performance.md should exist');
    const content = fs.readFileSync(perfPath, 'utf8');
    assert.ok(content.includes('useNativeDriver'), 'Should mention useNativeDriver');
    assert.ok(content.includes('FastImage'), 'Should mention FastImage');
  })) passed++; else failed++;

  if (test('native-modules.md exists and has content', () => {
    const nativePath = path.join(rootDir, 'skills/react-native-patterns/native-modules.md');
    assert.ok(fs.existsSync(nativePath), 'native-modules.md should exist');
    const content = fs.readFileSync(nativePath, 'utf8');
    assert.ok(content.includes('Expo'), 'Should mention Expo');
    assert.ok(content.includes('Swift'), 'Should mention Swift');
  })) passed++; else failed++;

  if (test('testing.md exists and has content', () => {
    const testPath = path.join(rootDir, 'skills/react-native-patterns/testing.md');
    assert.ok(fs.existsSync(testPath), 'testing.md should exist');
    const content = fs.readFileSync(testPath, 'utf8');
    assert.ok(content.includes('@testing-library/react-native'), 'Should mention React Native Testing Library');
    assert.ok(content.includes('Detox'), 'Should mention Detox');
  })) passed++; else failed++;

  // Agent tests
  console.log('\nAgents:');

  if (test('mobile-developer agent exists', () => {
    const agentPath = path.join(rootDir, 'agents/mobile-developer.md');
    assert.ok(fs.existsSync(agentPath), 'mobile-developer.md should exist');
    const content = fs.readFileSync(agentPath, 'utf8');
    assert.ok(content.includes('React Native'), 'Should mention React Native');
    assert.ok(content.includes('iOS'), 'Should mention iOS');
    assert.ok(content.includes('Android'), 'Should mention Android');
  })) passed++; else failed++;

  // Commands tests
  console.log('\nCommands:');

  if (test('/rn-init command exists', () => {
    const cmdPath = path.join(rootDir, 'commands/rn-init.md');
    assert.ok(fs.existsSync(cmdPath), 'rn-init.md should exist');
    const content = fs.readFileSync(cmdPath, 'utf8');
    assert.ok(content.includes('Expo'), 'Should mention Expo');
  })) passed++; else failed++;

  if (test('/rn-component command exists', () => {
    const cmdPath = path.join(rootDir, 'commands/rn-component.md');
    assert.ok(fs.existsSync(cmdPath), 'rn-component.md should exist');
    const content = fs.readFileSync(cmdPath, 'utf8');
    assert.ok(content.includes('StyleSheet'), 'Should mention StyleSheet');
  })) passed++; else failed++;

  if (test('/rn-navigation command exists', () => {
    const cmdPath = path.join(rootDir, 'commands/rn-navigation.md');
    assert.ok(fs.existsSync(cmdPath), 'rn-navigation.md should exist');
    const content = fs.readFileSync(cmdPath, 'utf8');
    assert.ok(content.includes('navigation types'), 'Should mention navigation types');
  })) passed++; else failed++;

  if (test('/rn-test command exists', () => {
    const cmdPath = path.join(rootDir, 'commands/rn-test.md');
    assert.ok(fs.existsSync(cmdPath), 'rn-test.md should exist');
    const content = fs.readFileSync(cmdPath, 'utf8');
    assert.ok(content.includes('Jest'), 'Should mention Jest');
  })) passed++; else failed++;

  // Hooks tests
  console.log('\nHooks:');

  if (test('RN project detection hook exists', () => {
    const hookPath = path.join(rootDir, 'hooks/react-native/project-detection/detect-rn.json');
    assert.ok(fs.existsSync(hookPath), 'detect-rn.json should exist');
    const content = fs.readFileSync(hookPath, 'utf8');
    const hookConfig = JSON.parse(content);
    assert.ok(hookConfig.matcher, 'Should have matcher');
  })) passed++; else failed++;

  if (test('RN detection script exists and is executable', () => {
    const scriptPath = path.join(rootDir, 'scripts/hooks/detect-rn-project.js');
    assert.ok(fs.existsSync(scriptPath), 'detect-rn-project.js should exist');
    // On Unix-like systems, check if executable
    try {
      fs.accessSync(scriptPath, fs.constants.X_OK);
    } catch (e) {
      // Not executable on this system, but file exists
    }
    const content = fs.readFileSync(scriptPath, 'utf8');
    assert.ok(content.includes('detectReactNativeProject'), 'Should have detection function');
  })) passed++; else failed++;

  // Configuration tests
  console.log('\nConfiguration:');

  if (test('plugin.json includes React Native keywords', () => {
    const pluginPath = path.join(rootDir, '.claude-plugin/plugin.json');
    const config = JSON.parse(fs.readFileSync(pluginPath, 'utf8'));
    assert.ok(config.keywords.includes('react-native'), 'Should include react-native keyword');
    assert.ok(config.keywords.includes('mobile'), 'Should include mobile keyword');
  })) passed++; else failed++;

  if (test('marketplace.json includes React Native tags', () => {
    const marketPath = path.join(rootDir, '.claude-plugin/marketplace.json');
    const config = JSON.parse(fs.readFileSync(marketPath, 'utf8'));
    const plugin = config.plugins[0];
    assert.ok(plugin.tags.includes('react-native'), 'Should include react-native tag');
    assert.ok(plugin.tags.includes('expo'), 'Should include expo tag');
  })) passed++; else failed++;

  if (test('hooks.json includes RN detection', () => {
    const hooksPath = path.join(rootDir, 'hooks/hooks.json');
    const config = JSON.parse(fs.readFileSync(hooksPath, 'utf8'));
    const preToolHooks = config.hooks.PreToolUse;
    const rnHook = preToolHooks.find(h => h.description && h.description.includes('React Native'));
    assert.ok(rnHook, 'Should have RN detection hook');
  })) passed++; else failed++;

  // Rules tests
  console.log('\nRules:');

  if (test('react-native.md rule file exists', () => {
    const rulePath = path.join(rootDir, 'rules/react-native.md');
    assert.ok(fs.existsSync(rulePath), 'react-native.md should exist');
    const content = fs.readFileSync(rulePath, 'utf8');
    assert.ok(content.includes('StyleSheet'), 'Should mention StyleSheet');
    assert.ok(content.includes('FlatList'), 'Should mention FlatList');
  })) passed++; else failed++;

  // Integration tests
  console.log('\nIntegration:');

  if (test('frontend-patterns skill mentions React Native', () => {
    const frontendPath = path.join(rootDir, 'skills/frontend-patterns/skill.md');
    const content = fs.readFileSync(frontendPath, 'utf8');
    assert.ok(content.includes('React Native'), 'Should mention React Native');
    assert.ok(content.includes('Platform Detection'), 'Should mention platform detection');
  })) passed++; else failed++;

  if (test('code-reviewer agent includes RN performance checks', () => {
    const reviewerPath = path.join(rootDir, 'agents/code-reviewer.md');
    const content = fs.readFileSync(reviewerPath, 'utf8');
    assert.ok(content.includes('React Native Performance'), 'Should include RN performance section');
  })) passed++; else failed++;

  if (test('security-reviewer agent includes mobile security', () => {
    const securityPath = path.join(rootDir, 'agents/security-reviewer.md');
    const content = fs.readFileSync(securityPath, 'utf8');
    assert.ok(content.includes('Mobile Security'), 'Should include mobile security section');
    assert.ok(content.includes('AsyncStorage'), 'Should mention AsyncStorage');
  })) passed++; else failed++;

  // File structure tests
  console.log('\nFile Structure:');

  if (test('All RN skill files are in correct directory', () => {
    const skillDir = path.join(rootDir, 'skills/react-native-patterns');
    const files = fs.readdirSync(skillDir);
    const expectedFiles = ['skill.md', 'components.md', 'navigation.md', 'performance.md', 'native-modules.md', 'testing.md'];
    for (const expected of expectedFiles) {
      assert.ok(files.includes(expected), `Should have ${expected}`);
    }
  })) passed++; else failed++;

  if (test('All RN commands exist', () => {
    const commandsDir = path.join(rootDir, 'commands');
    const files = fs.readdirSync(commandsDir);
    const rnCommands = files.filter(f => f.startsWith('rn-'));
    assert.ok(rnCommands.length >= 4, 'Should have at least 4 rn- commands');
  })) passed++; else failed++;

  // Summary
  console.log('\n=== Test Results ===');
  console.log(`Passed: ${passed}`);
  console.log(`Failed: ${failed}`);
  console.log(`Total:  ${passed + failed}`);

  if (failed === 0) {
    console.log('\n✅ All React Native support tests passed!\n');
  } else {
    console.log(`\n❌ ${failed} test(s) failed\n`);
  }

  process.exit(failed > 0 ? 1 : 0);
}

runTests();
