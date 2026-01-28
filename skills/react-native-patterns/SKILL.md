---
name: react-native-patterns
description: React Native development patterns including components, navigation, native modules, performance optimization, and cross-platform best practices for iOS and Android.
tags: [mobile, ios, android, expo, react-native]
dependencies:
  - frontend-patterns
  - coding-standards
---

# React Native Development Patterns

Modern React Native patterns for cross-platform mobile development, optimized for both iOS and Android.

## Project Type Detection

This skill is automatically activated when a React Native project is detected:

```typescript
// Detection indicators:
// - package.json contains: "react-native", "expo", or "@react-navigation/native"
// - App.tsx, App.jsx, or index.js exists with React Native imports
// - metro.config.js is present
```

## Core Principles

### 1. Platform-Aware Development

```typescript
import { Platform, StyleSheet, Text } from 'react-native'

// Detect platform at runtime
const isIOS = Platform.OS === 'ios'
const isAndroid = Platform.OS === 'android'

// Platform-specific styles
const styles = StyleSheet.create({
  container: {
    ...Platform.select({
      ios: {
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.2,
      },
      android: {
        elevation: 4,
      },
    }),
  },
})

// Platform-specific components
function PlatformButton() {
  return (
    <Text style={styles.text}>
      {Platform.select({
        ios: 'Press me',
        android: 'Tap me',
      })}
    </Text>
  )
}
```

### 2. Safe Area Handling

```typescript
import { useSafeAreaInsets } from 'react-native-safe-area-context'

function SafeScreen() {
  const insets = useSafeAreaInsets()

  return (
    <View style={{
      paddingTop: insets.top,
      paddingBottom: insets.bottom,
      paddingLeft: insets.left,
      paddingRight: insets.right,
    }}>
      {/* Content */}
    </View>
  )
}
```

### 3. Component Organization

```
src/
├── components/
│   ├── common/          # Cross-platform components
│   ├── ios/             # iOS-specific
│   └── android/         # Android-specific
├── screens/
├── navigation/
├── hooks/
├── services/
└── utils/
```

## Related Documentation

- **Components**: See `components.md` for React Native component patterns
- **Navigation**: See `navigation.md` for React Navigation setup
- **Performance**: See `performance.md` for optimization strategies
- **Native Modules**: See `native-modules.md` for native bridge patterns
- **Testing**: See `testing.md` for mobile testing strategies

## Quick Reference

| Pattern | iOS | Android | Expo |
|---------|-----|---------|-------|
| Safe Area | ✅ | ✅ | ✅ |
| Platform API | ✅ | ✅ | ✅ |
| Native Modules | ✅ | ✅ | ⚠️* |
| Deep Linking | ✅ | ✅ | ✅ |
| Push Notifications | ✅ | ✅ | ✅ |

*Expo requires custom dev client for native modules

## Integration with Web Skills

When developing for React Native, you can still leverage patterns from `frontend-patterns`:

- **State Management**: Context, Redux, Zustand patterns apply
- **Custom Hooks**: Hook patterns are framework-agnostic
- **Error Handling**: Adapt error boundaries for mobile
- **Testing**: Testing patterns translate with React Native Testing Library

## Expo vs React Native CLI

This skill supports both approaches:

### Expo (Recommended for most projects)
```bash
npx create-expo-app my-app
npx expo run:ios      # Requires macOS
npx expo run:android
```

### React Native CLI
```bash
npx react-native init MyApp --template react-native-template-typescript
cd MyApp && npx pod-install  # iOS only
```

---

## Agent Integration

For React Native development, use the following commands:

- **`/rn-test`** - TDD workflow for components and hooks
- **`/frontend-review`** - React 通用审查（共享代码）
- **`/rn-review`** - RN 特有审查（在 frontend-review 之后）
- **`/rn-build`** - Build error resolution for Metro, iOS, and Android

### When to Use Agents

```bash
# Implementing new features
/rn-test → Write tests first (RED/GREEN/REFACTOR)

# Before committing
/frontend-review → Review React patterns (shared code)
/rn-review → Review RN-specific issues

# Build failures
/rn-build → Fix Metro, iOS, or Android build errors
```

## Recommended Toolchain

### Testing (Required)
- `@testing-library/react-native` - Component testing
- `@testing-library/jest-native` - Custom matchers
- `react-test-renderer` - Snapshot testing

### E2E Testing (Optional)
- `Detox` - Gray-box E2E testing

### Linting
- ESLint with `@react-native-community/eslint-config`
- TypeScript strict mode
- `npx tsc --noEmit` for type checking

### Performance Monitoring
- `react-native-performance` for profiling
- `react-native-flipper` for debugging

### Development Tools
- Expo: `npx expo start --clear`
- React Native CLI: `npx react-native start --reset-cache`

---

**Remember**: React Native requires thinking mobile-first. Always consider platform differences, touch interactions, and mobile-specific UX patterns.
