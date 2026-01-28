---
description: Fix React Native build errors, Metro bundler issues, iOS/Android build failures, TypeScript errors, and dependency conflicts incrementally. Invokes the rn-build-resolver agent for minimal, surgical fixes.
---

# React Native Build and Fix

This command invokes the **rn-build-resolver** agent to incrementally fix React Native build errors with minimal changes.

## What This Command Does

1. **Detect Project Type**: Identify Expo vs React Native CLI
2. **Run Diagnostics**: Execute TypeScript, Metro, iOS, and Android builds
3. **Parse Errors**: Group by platform and sort by severity
4. **Fix Incrementally**: One error at a time
5. **Verify Each Fix**: Re-run build after each change
6. **Report Summary**: Show what was fixed and what remains

## When to Use

Use `/rn-build` when:
- Metro bundler fails to start or shows errors
- iOS build fails (pod install, Xcode errors)
- Android build fails (Gradle sync, SDK issues)
- TypeScript compilation errors
- Module resolution errors
- After pulling changes that break the build
- Native module linking fails

## Diagnostic Commands Run

### Project Type Detection
```bash
# Auto-detect project type
if [ -f "app.json" ] || [ -f "app.config.js" ]; then
  echo "Expo project detected"
else
  echo "React Native CLI project detected"
fi
```

### General Diagnostics
```bash
# TypeScript
npx tsc --noEmit

# Linting
npm run lint

# Dependencies
npm ls react react-native
```

### Metro Bundler
```bash
# For React Native CLI
npx react-native start --reset-cache

# For Expo
npx expo start --clear
```

### iOS
```bash
cd ios && pod install && cd ..

# Build
xcodebuild -workspace ios/MyApp.xcworkspace -scheme MyApp -configuration Debug build
```

### Android
```bash
cd android && ./gradlew clean && cd ..
cd android && ./gradlew assembleDebug && cd ..
```

## Example Session

```text
User: /rn-build

Agent:
# React Native Build Resolution

## Project Detection
Project Type: React Native CLI

## Initial Diagnostics

```bash
$ npx tsc --noEmit
src/components/Header.tsx:12:5 - error: Cannot find module '@styles/colors'

$ npx react-native start --reset-cache
Bundler failed with error: Unable to resolve module @utils/helpers

$ cd ios && pod install
[!] Invalid Podfile file: syntax error

Errors found: 3
```

## Fix 1: Missing Module Resolution

File: src/components/Header.tsx:12
Error: Cannot find module '@styles/colors'
Cause: Path alias not configured

Fixed tsconfig.json:
```json
{
  "compilerOptions": {
    "baseUrl": "./src",
    "paths": {
      "@/*": ["*"],
      "@styles/*": ["styles/*"],
      "@utils/*": ["utils/*"]
    }
  }
}
```

Fixed metro.config.js:
```javascript
const { resolver } = require('metro-resolver')

module.exports = {
  resolver: {
    alias: {
      '@': './src',
      '@styles': './src/styles',
      '@utils': './src/utils',
    },
  },
}
```

```bash
$ npx tsc --noEmit
# TS errors: 0 remaining

$ npx react-native start --reset-cache
# Metro: Success!
```

## Fix 2: Podfile Syntax Error

File: ios/Podfile:8
Error: Syntax error in Podfile

```ruby
# Before (broken)
platform :ios, '12.0'

# After (fixed)
platform :ios, '13.0'  # Updated minimum version
```

```bash
$ cd ios && pod install
Analyzing dependencies
Downloading dependencies
Installing dependencies (10)
Generated Pods project
Pod installation complete!
```

## Final Verification

```bash
$ npx tsc --noEmit
# No TypeScript errors

$ npx react-native bundle --platform ios --dev false --entry-file index.js --bundle-output /dev/null
# Bundle successful

$ cd ios && xcodebuild -workspace MyApp.xcworkspace -scheme MyApp -configuration Debug build
** BUILD SUCCEEDED **
```

## Summary

| Metric | Count |
|--------|-------|
| TypeScript errors fixed | 1 |
| Metro errors fixed | 1 |
| iOS build errors fixed | 1 |
| Files modified | 2 |
| Remaining issues | 0 |

Build Status: ✅ SUCCESS
```

## Common Errors Fixed

### Metro Bundler Errors
| Error | Typical Fix |
|-------|-------------|
| `Unable to resolve module` | Add alias to metro.config.js, install missing dependency |
| `TransformError` | Clear cache, check syntax, reinstall node_modules |
| `Module not found` | Fix import path, install dependency |

### iOS Build Errors
| Error | Typical Fix |
|-------|-------------|
| `pod install fails` | Update CocoaPods repo, clean Pods folder |
| `Xcode version mismatch` | Update Command Line Tools, switch Xcode version |
| `Swift version mismatch` | Add post_install hook to Podfile |

### Android Build Errors
| Error | Typical Fix |
|-------|-------------|
| `Gradle sync failed` | Clean Gradle cache, update Gradle wrapper |
| `SDK version mismatch` | Install missing SDK via sdkmanager |
| `Dependency conflict` | Add resolutionStrategy to build.gradle |
| `Dex build error` | Enable multiDexEnabled |

### TypeScript Errors
| Error | Typical Fix |
|-------|-------------|
| `Cannot find module` | Install @types package, fix path alias |
| `Type X not assignable` | Fix type definition, add type assertion |
| `Module resolution failed` | Update tsconfig baseUrl/paths |

## Fix Strategy

1. **TypeScript errors first** - Type safety prevents runtime issues
2. **Metro errors second** - Bundler must work for development
3. **iOS build third** - iOS developers need working builds
4. **Android build fourth** - Android developers need working builds
5. **One fix at a time** - Verify each change
6. **Minimal changes** - Don't refactor, just fix

## Platform-Specific Workflows

### Expo Workflow
```text
1. npx expo doctor
   ↓
2. npx tsc --noEmit
   ↓ Errors?
3. Fix TS errors
   ↓
4. npx expo start --clear
   ↓ Metro errors?
5. Fix Metro issues
   ↓
6. npx expo run:ios
   ↓ iOS errors?
7. Fix iOS issues
   ↓
8. npx expo run:android
   ↓ Android errors?
9. Fix Android issues
   ↓
10. Done!
```

### React Native CLI Workflow
```text
1. npx tsc --noEmit
   ↓ Errors?
2. Fix TS errors
   ↓
3. npx react-native start --reset-cache
   ↓ Metro errors?
4. Fix Metro issues
   ↓
5. cd ios && pod install && cd ..
   ↓ iOS errors?
6. Fix iOS issues
   ↓
7. cd android && ./gradlew assembleDebug && cd ..
   ↓ Android errors?
8. Fix Android issues
   ↓
9. Done!
```

## Stop Conditions

The agent will stop and report if:
- Same error persists after 3 attempts
- Fix introduces more errors
- Requires external tools installation (Xcode, Android Studio)
- Error requires upgrading React Native version
- Native module requires manual configuration
- Hardware issue (device/emulator not detected)

## Output Format

After each fix attempt:
```text
[FIXED] metro.config.js:15
Error: Unable to resolve @styles/colors
Fix: Added path alias to metro.config.js

Remaining errors: 2
```

Final summary:
```text
Build Status: SUCCESS/FAILED
Errors Fixed: N
TypeScript errors: N
Metro errors: N
iOS errors: N
Android errors: N
Files Modified: list
Remaining Issues: list (if any)
```

## Common Diagnostic Commands

### Check project health
```bash
# Expo
npx expo doctor

# React Native CLI
npx react-native doctor

# General
npm ls react react-native
```

### Clean everything
```bash
# Watchman
watchman watch-del-all

# Metro cache
rm -rf $TMPDIR/react-*
rm -rf node_modules/.cache

# Reinstall dependencies
rm -rf node_modules
npm install

# iOS
cd ios && rm -rf Pods Podfile.lock && pod install && cd ..

# Android
cd android && ./gradlew clean && cd ..
```

## Related Commands

- `/rn-test` - Run tests after build succeeds
- `/rn-review` - Review code quality
- `/tdd` - TDD workflow for new features

## Related

- Agent: `agents/rn-build-resolver.md`
- Skill: `skills/react-native-patterns/`
