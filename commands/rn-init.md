---
name: rn-init
description: Initialize a new React Native project with best practices and opinionated defaults
---

# /rn-init

Initialize a new React Native project with opinionated defaults and best practices.

## Usage

```
/rn-init [project-name] [options]
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--expo` | Use Expo (recommended for most projects) | true |
| `--cli` | Use React Native CLI instead of Expo | false |
| `--typescript` | Enable TypeScript | true |
| `--navigation` | Include React Navigation setup | true |
| `--state` | State management: zustand, redux, none | zustand |
| `--styling` | Styling: stylesheet, nativewind,-ui-kitten | stylesheet |
| `--testing` | Include testing setup | true |

## Examples

```bash
# Basic Expo project
/rn-init MyApp

# Expo with TypeScript and Navigation
/rn-init MyApp --expo --typescript --navigation

# React Native CLI project
/rn-init MyApp --cli

# Full-featured project
/rn-init MyApp --typescript --navigation --state zustand --testing
```

## What Gets Created

### Project Structure

```
MyApp/
├── src/
│   ├── navigation/          # Navigation configuration
│   │   ├── types.ts         # Navigation type definitions
│   │   ├── RootNavigator.tsx
│   │   ├── AuthNavigator.tsx
│   │   └── AppNavigator.tsx
│   ├── screens/            # Screen components
│   │   ├── auth/
│   │   ├── home/
│   │   └── profile/
│   ├── components/         # Reusable components
│   │   ├── common/
│   │   ├── ios/
│   │   └── android/
│   ├── hooks/              # Custom hooks
│   ├── services/           # API and external services
│   ├── utils/              # Utility functions
│   └── types/              # TypeScript types
├── assets/                 # Images, fonts, etc.
├── App.tsx                 # App entry point
├── package.json
├── tsconfig.json
└── metro.config.js         # (CLI only)
```

### Included Features

**Navigation Setup**
- React Navigation with type safety
- Auth flow navigator
- Tab navigator for main app
- Deep linking configuration

**State Management**
- Zustand for global state
- Context API for component state
- React Query for server state

**Styling**
- StyleSheet utilities
- Platform-specific styles
- Theme system

**Testing**
- React Native Testing Library
- Jest configuration
- Mock setup for native modules

**Development**
- ESLint for React Native
- Prettier configuration
- Absolute imports
- Environment variables

## After Installation

```bash
cd MyApp

# For Expo
npx expo start

# For React Native CLI
# iOS (macOS only)
npx pod-install
npx react-native run-ios

# Android
npx react-native run-android
```

## Next Steps

1. Configure app name and display name
2. Set up deep linking URLs
3. Configure splash screen and icons
4. Set up push notifications
5. Configure analytics

## See Also

- `/rn-component` - Create new components
- `/rn-navigation` - Set up navigation
- `/rn-native` - Create native modules

---

**Tip**: Use Expo unless you need custom native modules. It provides a much faster development experience.
