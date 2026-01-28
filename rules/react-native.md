# React Native Development Rules

Rules and guidelines specific to React Native mobile development.

## Code Style

### File Organization

```
✅ GOOD
src/
├── components/
│   ├── common/
│   ├── ios/
│   └── android/
├── screens/
├── navigation/
├── hooks/
├── services/
└── utils/

❌ BAD
src/
├── Components/
├── Screens/
├── Navigation/
└── randomFiles/
```

### Platform-Specific Files

Use `.ios.` and `.android.` file extensions for platform-specific code:

```
MyComponent.ios.tsx    // iOS specific
MyComponent.android.tsx // Android specific
MyComponent.tsx         // Shared (exports platform file)
```

### Imports

```typescript
// ✅ GOOD: Grouped imports
import React from 'react'
import { View, Text, StyleSheet } from 'react-native'
import { useNavigation } from '@react-navigation/native'
import { Button } from '@/components/common'
import { useAuth } from '@/hooks/useAuth'

// ❌ BAD: Unorganized imports
import { Button } from '@/components/common'
import React from 'react'
import { useAuth } from '@/hooks/useAuth'
import { View } from 'react-native'
```

## Component Rules

### 1. Use StyleSheet, Not Inline Styles

```typescript
// ✅ GOOD
const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
  },
})

function MyComponent() {
  return <View style={styles.container} />
}

// ❌ BAD
function MyComponent() {
  return <View style={{ flex: 1, padding: 16 }} />
}
```

### 2. Always Provide keyExtractor for FlatList

```typescript
// ✅ GOOD
<FlatList
  data={items}
  keyExtractor={(item) => item.id}
  renderItem={renderItem}
/>

// ❌ BAD
<FlatList
  data={items}
  renderItem={renderItem}
/>
```

### 3. Memoize List Items

```typescript
// ✅ GOOD
const ListItem = memo(({ item, onPress }) => (
  <TouchableOpacity onPress={onPress}>
    <Text>{item.title}</Text>
  </TouchableOpacity>
))

// ❌ BAD
function ListItem({ item, onPress }) {
  return (
    <TouchableOpacity onPress={onPress}>
      <Text>{item.title}</Text>
    </TouchableOpacity>
  )
}
```

### 4. Use Platform-Selective Code

```typescript
// ✅ GOOD
const styles = StyleSheet.create({
  container: {
    ...Platform.select({
      ios: { shadowColor: '#000' },
      android: { elevation: 4 },
    }),
  },
})

// ❌ BAD
const styles = StyleSheet.create({
  container: Platform.OS === 'ios' ? { shadowColor: '#000' } : { elevation: 4 },
})
```

## Performance Rules

### 1. Optimize Images

```typescript
// ✅ GOOD: Use FastImage
import FastImage from 'react-native-fast-image'

<FastImage
  source={{ uri: imageUrl }}
  resizeMode={FastImage.resizeMode.cover}
/>

// ❌ BAD: Use Image for network images
<Image source={{ uri: imageUrl }} />
```

### 2. Use Native Driver for Animations

```typescript
// ✅ GOOD
Animated.timing(opacity, {
  toValue: 1,
  useNativeDriver: true,
}).start()

// ❌ BAD
Animated.timing(opacity, {
  toValue: 1,
  useNativeDriver: false,
}).start()
```

### 3. Avoid Inline Functions in render

```typescript
// ✅ GOOD
const handlePress = useCallback(() => {
  doSomething()
}, [dependency])

<TouchableOpacity onPress={handlePress} />

// ❌ BAD
<TouchableOpacity onPress={() => doSomething()} />
```

## Navigation Rules

### 1. Use Type-Safe Navigation

```typescript
// ✅ GOOD: Define navigation types
import type { AppStackParamList } from '@/navigation/types'

type ProfileScreenProps = NativeStackScreenProps<
  AppStackParamList,
  'Profile'
>

// ❌ BAD: No types
function ProfileScreen({ route, navigation }) {
  const userId = route.params.userId // What type is this?
}
```

### 2. Validate Deep Link URLs

```typescript
// ✅ GOOD
const validateUrl = (url: string): boolean => {
  const allowedDomains = ['myapp.com', 'www.myapp.com']
  const parsed = new URL(url)
  return allowedDomains.includes(parsed.hostname)
}

// ❌ BAD: Use deep link URLs without validation
const handleDeepLink = (url: string) => {
  navigation.navigate(url)
}
```

## Security Rules

### 1. Don't Store Secrets in AsyncStorage

```typescript
// ✅ GOOD: Use secure storage
import * as Keychain from 'react-native-keychain'

await Keychain.setGenericPassword('server', authToken)

// ❌ BAD: Store tokens in plain text
await AsyncStorage.setItem('authToken', authToken)
```

### 2. Validate Deep Link Inputs

```typescript
// ✅ GOOD
const handleDeepLink = (url: string) => {
  const parsed = new URL(url)
  if (parsed.protocol !== 'myapp:') {
    throw new Error('Invalid deep link')
  }
  // Process link...
}

// ❌ BAD
const handleDeepLink = (url: string) => {
  navigation.navigate(url) // What if URL is malicious?
}
```

### 3. Use HTTPS for API Calls

```typescript
// ✅ GOOD
fetch('https://api.example.com/data')

// ❌ BAD
fetch('http://api.example.com/data')
```

## Testing Rules

### 1. Use testID for Element Selection

```typescript
// ✅ GOOD
<Button testID="submit-button" onPress={handleSubmit} />

// Find in tests: getByTestId('submit-button')

// ❌ BAD: Use accessibility or text
<Button onPress={handleSubmit} />

// Find in tests: getByText('Submit') // Brittle!
```

### 2. Mock Native Modules

```typescript
// ✅ GOOD
jest.mock('react-native/Libraries/Animated/NativeAnimatedHelper')
jest.mock('@react-native-async-storage/async-storage', () =>
  require('@react-native-async-storage/async-storage/jest/async-storage-mock')
)

// ❌ BAD: Don't test with actual native modules
// Tests will fail or be slow
```

## TypeScript Rules

### 1. Define Props Interfaces

```typescript
// ✅ GOOD
interface ButtonProps {
  title: string
  onPress: () => void
  disabled?: boolean
  variant?: 'primary' | 'secondary'
}

export function Button({ title, onPress, disabled, variant = 'primary' }: ButtonProps) {
  // ...
}

// ❌ BAD
export function Button(props: any) {
  // What props does this accept?
}
```

### 2. Use Strict TypeScript

```json
// tsconfig.json
{
  "extends": "@react-native/typescript-config",
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true
  }
}
```

## Common Anti-Patterns

### ❌ Don't Do This

```typescript
// 1. Don't use console.log in production
console.log('User data:', userData)

// 2. Don't store large objects in AsyncStorage
await AsyncStorage.setItem('largeData', JSON.stringify(largeArray))

// 3. Don't forget cleanup in useEffect
useEffect(() => {
  const subscription = someEmitter.addListener('event', handler)
  // Missing: return () => subscription.remove()
}, [])

// 4. Don't use setTimeout/setInterval without cleanup
useEffect(() => {
  const timer = setTimeout(() => {}, 1000)
  return () => clearTimeout(timer)
}, [])

// 5. Don't ignore platform differences
<View style={{ height: 44 }} /> // Different on iOS vs Android
```

### ✅ Do This Instead

```typescript
// 1. Use proper logging
import { logger } from '@/services/logger'
logger.info('User logged in')

// 2. Use proper storage for large data
import SQLite from 'react-native-sqlite-storage'

// 3. Always cleanup
useEffect(() => {
  const subscription = someEmitter.addListener('event', handler)
  return () => subscription.remove()
}, [])

// 4. Always clean up timers
useEffect(() => {
  const timer = setTimeout(() => {}, 1000)
  return () => clearTimeout(timer)
}, [])

// 5. Use platform-specific values
const headerHeight = Platform.select({
  ios: 44,
  android: 56,
})
<View style={{ height: headerHeight }} />
```

## File Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Components | PascalCase | `UserCard.tsx` |
| Hooks | camelCase with 'use' prefix | `useAuth.ts` |
| Services | camelCase | `apiClient.ts` |
| Utils | camelCase | `dateFormatter.ts` |
| Types | PascalCase with 'Types' suffix | `NavigationTypes.ts` |
| Constants | SCREAMING_SNAKE_CASE | `API_ENDPOINTS.ts` |

## Code Review Checklist

Before submitting PR, verify:

- [ ] No `console.log` statements
- [ ] All components have TypeScript interfaces
- [ ] FlatList has keyExtractor
- [ ] Images are optimized
- [ ] Styles use StyleSheet
- [ ] Platform-specific code is properly organized
- [ ] Navigation types are defined
- [ ] Tests use testID props
- [ ] No secrets in code
- [ ] AsyncStorage not used for sensitive data
- [ ] API calls use HTTPS
- [ ] Event listeners are cleaned up

## Agent Usage Rules

React Native projects must use specialized agents for code quality and development workflow:

### Required Commands

- **`/rn-test`** - MUST be used when:
  - Implementing new components or hooks
  - Adding features to existing screens
  - Fixing bugs (write failing test first)
  - Building custom hooks

- **`/frontend-review`** - MUST be used for:
  - Reviewing React patterns (shared code)
  - Reviewing hooks, components, TypeScript
  - Code shared between web and mobile

- **`/rn-review`** - MUST be used for:
  - Reviewing RN-specific issues (Platform API, native modules)
  - Reviewing FlatList optimization
  - Reviewing mobile-specific security
  - Use AFTER `/frontend-review` for complete review

- **`/rn-build`** - MUST be used when:
  - Metro bundler fails to start
  - iOS build fails (pod install, Xcode)
  - Android build fails (Gradle)
  - TypeScript compilation errors

### Development Workflow

```text
1. /rn-test → Write tests first (RED/GREEN/REFACTOR)
2. Implement → Write minimal code to pass tests
3. /frontend-review → Review React patterns (shared code)
4. /rn-review → Review RN-specific issues
5. /rn-build → Fix any build issues (if needed)
6. Commit → Only when reviewers approve
```

### Approval Criteria

- ✅ **Approve**: No CRITICAL or HIGH issues from `/frontend-review` or `/rn-review`
- ⚠️ **Warning**: Only MEDIUM issues (merge with caution)
- ❌ **Block**: CRITICAL or HIGH issues found from either reviewer - must fix before committing

---

**Remember**: React Native is not web. Mobile devices have different constraints, performance characteristics, and security concerns. Always consider the mobile context when writing code.
