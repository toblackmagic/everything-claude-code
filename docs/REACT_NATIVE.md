# React Native Support

Complete React Native development support for Claude Code, including skills, agents, commands, and automated detection.

## Overview

This plugin now includes comprehensive support for React Native mobile development, covering both Expo and React Native CLI workflows, with patterns for iOS and Android platforms.

## Features

### 📚 Skill Modules

**Location:** `skills/react-native-patterns/`

| Module | Description |
|--------|-------------|
| `skill.md` | Main skill definition with platform detection |
| `components.md` | Component patterns, FlatList optimization, custom hooks |
| `navigation.md` | React Navigation setup with type safety |
| `performance.md` | Performance optimization strategies |
| `native-modules.md` | Native module bridging guide |
| `testing.md` | Testing with Jest, React Native Testing Library, Detox |

### 🤖 Agent

**Location:** `agents/mobile-developer.md`

Specialized `mobile-developer` agent for React Native development tasks:
- Project detection and validation
- Platform-specific code guidance
- Native module integration
- Mobile performance optimization

### ⚡ Commands

| Command | Description |
|---------|-------------|
| `/rn-init` | Initialize new React Native project with best practices |
| `/rn-component` | Generate React Native components with TypeScript |
| `/rn-navigation` | Set up React Navigation with type safety |
| `/rn-test` | Configure testing infrastructure |

### 🔗 Hooks

**Location:** `hooks/react-native/`

- **Project Detection**: Automatically detects React Native projects
- **Smart Suggestions**: Shows relevant commands when RN project is detected

### 📋 Rules

**Location:** `rules/react-native.md`

Coding standards and best practices specific to React Native development.

## Quick Start

### 1. Automatic Detection

The plugin automatically detects React Native projects:

```bash
npm install
```

**Output:**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚡  Expo project detected
   React Native: 0.72.x
   Type: Managed Workflow
   Platforms: • iOS • Android

   🔧 Available commands:
     /rn-init      - Initialize a new RN project
     /rn-component - Create a new component
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 2. Create a New Project

```
/rn-init MyApp
```

This creates a fully configured React Native project with:
- TypeScript configuration
- Navigation setup
- State management
- Testing infrastructure
- ESLint + Prettier

### 3. Create Components

```
/rn-component Button
/rn-component UserCard --type memo
```

### 4. Set Up Navigation

```
/rn-navigation --auth --bottom-tabs --deep-link
```

## Project Structure

```
everything-claude-code/
├── skills/
│   └── react-native-patterns/          # RN development patterns
│       ├── skill.md
│       ├── components.md
│       ├── navigation.md
│       ├── performance.md
│       ├── native-modules.md
│       └── testing.md
├── agents/
│   └── mobile-developer.md             # Mobile development specialist
├── commands/
│   ├── rn-init.md                      # Project initialization
│   ├── rn-component.md                 # Component generation
│   ├── rn-navigation.md                # Navigation setup
│   └── rn-test.md                      # Testing configuration
├── hooks/
│   └── react-native/
│       └── project-detection/
│           └── detect-rn.json          # Auto-detection hook
├── scripts/
│   └── hooks/
│       └── detect-rn-project.js        # Detection script
└── rules/
    └── react-native.md                 # RN coding standards
```

## Platform Support

| Feature | iOS | Android | Expo |
|---------|-----|---------|-------|
| Component Patterns | ✅ | ✅ | ✅ |
| Navigation | ✅ | ✅ | ✅ |
| Performance | ✅ | ✅ | ✅ |
| Native Modules | ✅ | ✅ | ⚠️* |
| Testing | ✅ | ✅ | ✅ |

*Expo requires custom dev client for native modules

## Usage Examples

### Developing with the Mobile Agent

When working in a React Native project, Claude will automatically use the `mobile-developer` agent:

```
User: Create a user profile screen with safe area handling

Claude: [Using mobile-developer agent]
I'll create a profile screen with proper safe area handling...

[Generates code with useSafeAreaInsets hook, Platform-specific styles, etc.]
```

### Code Review Integration

The `code-reviewer` agent now includes React Native performance checks:

```typescript
// ❌ FLAGGED: Unoptimized FlatList
<FlatList data={items} renderItem={renderItem} />

// ✅ CORRECT: Optimized with keyExtractor and memo
<FlatList
  data={items}
  keyExtractor={(item) => item.id}
  renderItem={renderItem}
  removeClippedSubviews={true}
/>
```

### Security Review

The `security-reviewer` agent includes mobile-specific security checks:

```typescript
// ❌ FLAGGED: Sensitive data in AsyncStorage
await AsyncStorage.setItem('authToken', token)

// ✅ CORRECT: Use secure storage
await Keychain.setGenericPassword('auth', token)
```

## Integration with Existing Skills

### frontend-patterns

Updated to include platform detection guidance:

```typescript
// Check if running in React Native
const isReactNative = typeof navigator !== 'undefined' &&
  navigator.product === 'ReactNative'
```

### Shared Patterns

These patterns work in **both** web and React Native:
- Custom Hooks (`useToggle`, `useQuery`, `useDebounce`)
- State Management (Context, Reducer, Zustand, Redux)
- Component Composition patterns
- Error Boundaries

## Testing

### Run Tests

```bash
# Test React Native support
node tests/rn-support.test.js

# Run all tests
npm test
```

### Test Coverage

- ✅ 22/22 tests passing
- ✅ All modules verified
- ✅ Integration tests passing
- ✅ Configuration validated

## Configuration Files

### Updated Files

| File | Changes |
|------|---------|
| `plugin.json` | Added `react-native`, `mobile`, `expo`, `ios`, `android` keywords |
| `marketplace.json` | Added mobile development tags |
| `hooks.json` | Added React Native project detection hook |
| `frontend-patterns/skill.md` | Added platform detection guidance |
| `code-reviewer.md` | Added RN performance checks |
| `security-reviewer.md` | Added mobile security checks |

## Best Practices

### When Working with React Native

1. **Use the mobile-developer agent** - It specializes in RN development
2. **Follow the react-native.md rules** - Coding standards for mobile
3. **Test on both platforms** - iOS and Android behavior can differ
4. **Use Platform.select()** - For platform-specific styles
5. **Optimize lists** - Always use FlatList with proper optimization
6. **Secure data properly** - Use Keychain for sensitive data

### Common Patterns

```typescript
// Platform-specific code
const styles = StyleSheet.create({
  container: {
    ...Platform.select({
      ios: { shadowColor: '#000' },
      android: { elevation: 4 },
    }),
  },
})

// Safe area handling
import { useSafeAreaInsets } from 'react-native-safe-area-context'

function Screen() {
  const insets = useSafeAreaInsets()
  return (
    <View style={{ paddingTop: insets.top }}>
      {/* Content */}
    </View>
  )
}

// Optimized list
<FlatList
  data={items}
  keyExtractor={(item) => item.id}
  renderItem={renderItem}
  removeClippedSubviews={true}
  maxToRenderPerBatch={10}
/>
```

## Contributing

When contributing React Native improvements:

1. Update relevant skill files in `skills/react-native-patterns/`
2. Add tests to `tests/rn-support.test.js`
3. Update this README with new features
4. Ensure all tests pass before submitting

## Support

For issues or questions about React Native support:

1. Check the skill files in `skills/react-native-patterns/`
2. Review `rules/react-native.md` for coding standards
3. Use `/rn-*` commands for quick scaffolding
4. Let Claude detect your RN project automatically

---

**Version:** 1.0.0
**Last Updated:** 2024-01-25
**Maintained by:** Everything Claude Code
