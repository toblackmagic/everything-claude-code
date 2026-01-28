---
description: Comprehensive React Native code review for performance optimization, platform compatibility, navigation safety, and mobile security. Performs two-layer review: frontend-reviewer for shared React patterns, then rn-reviewer for RN-specific issues.
---

# React Native Code Review

This command performs a **two-layer comprehensive review** for React Native code:
1. **frontend-reviewer** agent for shared React patterns (hooks, TypeScript, components)
2. **rn-reviewer** agent for React Native-specific issues (Platform API, native modules, FlatList)

## What This Command Does

### Layer 1: Frontend Review (frontend-reviewer)
1. **Identify RN Changes**: Find modified `.tsx`, `.ts`, `.jsx`, `.js` files via `git diff`
2. **Run Static Analysis**: Execute ESLint, TypeScript, and tests
3. **Component Pattern Review**: Props interfaces, component structure, file organization
4. **Hooks Review**: Rules of Hooks, dependency arrays, custom hook patterns, useEffect cleanup
5. **TypeScript Review**: Type definitions, generic components, event handling types
6. **Performance Review**: React.memo usage, useCallback/useMemo patterns, unnecessary re-renders
7. **Security Scan**: Input validation, XSS prevention, HTTPS enforcement

### Layer 2: RN-Specific Review (rn-reviewer)
1. **Platform Review**: Check iOS/Android compatibility and safe area handling
2. **FlatList Optimization**: keyExtractor, removeClippedSubviews, maxToRenderPerBatch
3. **Native Integration**: StyleSheet vs inline, FastImage, useNativeDriver, Bridge calls
4. **Memory Analysis**: Verify useEffect cleanup and timer/event listener removal
5. **Mobile Security**: AsyncStorage vs Keychain, deep link validation, native module permissions

## When to Use

Use `/rn-review` when:
- After writing or modifying React Native components
- Before committing React Native changes
- Reviewing pull requests with mobile code
- Onboarding to a React Native codebase
- Optimizing app performance
- Preparing for production release

## Review Categories

### CRITICAL (Must Fix)
- Memory leaks (event listeners, timers, subscriptions not cleaned up)
- AsyncStorage storing sensitive data (tokens, passwords)
- Missing HTTPS for API calls
- Deep link injection vulnerabilities
- FlatList without keyExtractor (causes crashes and poor performance)
- Hardcoded secrets (API keys, credentials)

### HIGH (Should Fix)
- Missing component memoization (performance)
- Missing useCallback/useMemo for expensive operations
- Unsafe useEffect cleanup
- Platform-specific code not properly organized
- Missing navigation prop types
- Missing safe area insets handling
- Timer leaks (setTimeout/setInterval not cleared)

### MEDIUM (Consider)
- Inline styles instead of StyleSheet
- Missing testID props for testing
- TypeScript `any` types
- Large components (>300 lines)
- Native driver not used for animations
- Image component used instead of FastImage
- Missing Platform.select for platform-specific code

## Automated Checks Run

```bash
# TypeScript checking
npx tsc --noEmit

# Linting
npm run lint
# or
npx eslint . --ext .ts,.tsx,.js,.jsx

# Testing
npm test

# Expo doctor (if Expo)
npx expo doctor

# React Native doctor (if CLI)
npx react-native doctor
```

## Example Usage

```text
User: /rn-review

Agent:
# React Native Code Review Report

## Files Reviewed
- src/components/UserList.tsx (modified)
- src/screens/HomeScreen.tsx (modified)
- src/hooks/useAuth.ts (modified)

## Static Analysis Results
✓ TypeScript: No errors
⚠️ ESLint: 2 warnings

## Issues Found

[CRITICAL] Memory Leak - Event Listener Not Cleaned Up
File: src/screens/HomeScreen.tsx:28
Issue: AppState listener added but never removed
```typescript
useEffect(() => {
  const subscription = AppState.addEventListener('change', handleAppStateChange)
  // Missing: return () => subscription.remove()
}, [])
```
Fix: Add cleanup function
```typescript
useEffect(() => {
  const subscription = AppState.addEventListener('change', handleAppStateChange)
  return () => subscription.remove()
}, [])
```

[HIGH] Missing FlatList Optimization
File: src/components/UserList.tsx:42
Issue: FlatList missing keyExtractor causing poor performance
```typescript
<FlatList
  data={users}
  renderItem={renderItem}
/>
```
Fix: Add keyExtractor and performance props
```typescript
<FlatList
  data={users}
  keyExtractor={(item) => item.id}
  renderItem={renderItem}
  removeClippedSubviews={true}
  maxToRenderPerBatch={10}
  windowSize={5}
/>
```

[HIGH] AsyncStorage Storing Sensitive Data
File: src/hooks/useAuth.ts:15
Issue: Auth token stored in plain text AsyncStorage
```typescript
await AsyncStorage.setItem('authToken', token)
```
Fix: Use secure storage
```typescript
import * as Keychain from 'react-native-keychain'
await Keychain.setGenericPassword('auth', token)
```

[MEDIUM] Missing Memoization
File: src/components/UserList.tsx:12
Issue: List item component not memoized, causes unnecessary re-renders
```typescript
function ListItem({ item, onPress }) {
  return <TouchableOpacity onPress={() => onPress(item.id)}>
```
Fix: Wrap with React.memo and useCallback
```typescript
const ListItem = memo(({ item, onPress }) => (
  <TouchableOpacity onPress={onPress}>
  ))

const handlePress = useCallback((id) => {
  navigation.navigate('UserDetail', { userId: id })
}, [navigation])
```

## Summary
- CRITICAL: 2
- HIGH: 2
- MEDIUM: 1

Recommendation: ❌ Block merge until CRITICAL issues are fixed

## Platform-Specific Issues Detected
- iOS: Missing safe area handling on HomeScreen
- Android: No issues detected

## Performance Warnings
- UserList may have poor scroll performance with large lists
- Consider using FastImage for avatar images
```

## Approval Criteria

| Status | Condition |
|--------|-----------|
| ✅ Approve | No CRITICAL or HIGH issues |
| ⚠️ Warning | Only MEDIUM issues (merge with caution) |
| ❌ Block | CRITICAL or HIGH issues found |

## Common Review Patterns

### Performance Review Checklist
```markdown
- [ ] FlatList has keyExtractor
- [ ] List items are memoized
- [ ] Callbacks use useCallback
- [ ] Expensive computations use useMemo
- [ ] Images use FastImage for network URLs
- [ ] Animations use native driver
```

### Platform Review Checklist
```markdown
- [ ] Platform.select used for platform-specific code
- [ ] Safe area insets handled
- [ ] Platform-specific files (.ios./.android.) used when appropriate
- [ ] Platform differences tested
```

### Memory Review Checklist
```markdown
- [ ] All useEffect have cleanup functions
- [ ] Event listeners removed in cleanup
- [ ] Timers cleared in cleanup
- [ ] Subscriptions cancelled in cleanup
- [ ] No closure stale state issues
```

### Security Review Checklist
```markdown
- [ ] No sensitive data in AsyncStorage
- [ ] Deep link URLs validated
- [ ] API calls use HTTPS
- [ ] No hardcoded secrets
- [ ] User inputs validated
```

## Integration with Other Commands

- Use `/rn-test` first to ensure tests pass
- Use `/rn-build` if build errors occur
- Use `/frontend-review` for React Web code or shared code
- Use `/rn-review` for complete React Native review (includes frontend review automatically)
- Use `/code-review` for non-frontend specific concerns

## Project Type Detection

The command automatically detects project type:

```bash
# Expo
if [ -f "app.json" ] || [ -f "app.config.js" ]; then
  npx expo doctor
fi

# React Native CLI
if [ -d "ios" ] && [ -d "android" ]; then
  npx react-native doctor
fi
```

## Platform-Specific Concerns

### iOS-Specific Reviews
- Shadow performance (expensive on iOS)
- Safe area with notches
- Dynamic Type support
- Dark mode adaptation
- Memory footprint (iOS has strict limits)

### Android-Specific Reviews
- Elevation shadow performance
- Back button handling
- Permission runtime handling
- Hardware acceleration
- Proguard/R8 configuration

## Related

- Agent: `agents/rn-reviewer.md`
- Skills: `skills/react-native-patterns/`
- Skill: `skills/frontend-patterns/`
- Rules: `rules/react-native.md`
