---
description: Enforce TDD workflow for React Native. Write tests with React Native Testing Library first, then implement. Verify 80%+ coverage with Jest.
---

# React Native TDD Command

This command enforces test-driven development methodology for React Native code using mobile testing best practices.

## What This Command Does

1. **Define Component Interface**: Scaffold props and types first
2. **Write Failing Tests**: Create comprehensive test cases (RED)
3. **Run Tests**: Verify tests fail for the right reason
4. **Implement Component**: Write minimal code to pass (GREEN)
5. **Refactor**: Improve while keeping tests green
6. **Check Coverage**: Ensure 80%+ coverage

## When to Use

Use `/rn-test` when:
- Implementing new React Native components
- Adding test coverage to existing components
- Fixing bugs (write failing test first)
- Building custom hooks
- Creating navigation screens
- Writing native module wrappers

## TDD Cycle

```
RED     → Write failing test (React Native Testing Library)
GREEN   → Implement minimal code to pass
REFACTOR → Improve code, tests stay green
REPEAT  → Next test case
```

## Testing Toolchain

### Required Dependencies
```json
{
  "devDependencies": {
    "@testing-library/react-native": "^12.0.0",
    "@testing-library/jest-native": "^5.4.0",
    "react-test-renderer": "^18.2.0",
    "jest": "^29.0.0",
    "@types/jest": "^29.0.0"
  }
}
```

### E2E Testing (Optional)
```json
{
  "devDependencies": {
    "detox": "^20.0.0"
  }
}
```

## Example Session

```text
User: /rn-test I need a UserCard component that displays user info

Agent:
# TDD Session: UserCard Component

## Step 1: Define Interface

```typescript
// src/components/UserCard.tsx
import React from 'react'
import { View, Text, StyleSheet } from 'react-native'

export interface UserCardProps {
  user: {
    id: string
    name: string
    email: string
    avatar?: string
  }
  onPress?: (userId: string) => void
  testID?: string
}

export function UserCard({ user, onPress, testID }: UserCardProps): React.JSX.Element {
  throw new Error('Not implemented')
}

const styles = StyleSheet.create({
  container: {
    padding: 16,
    backgroundColor: '#fff',
  },
})
```

## Step 2: Write Tests (RED)

```typescript
// src/components/UserCard.test.tsx
import React from 'react'
import { render, fireEvent } from '@testing-library/react-native'
import { UserCard } from './UserCard'

describe('UserCard', () => {
  const mockUser = {
    id: '123',
    name: 'John Doe',
    email: 'john@example.com',
    avatar: 'https://example.com/avatar.jpg',
  }

  it('renders user name and email', () => {
    const { getByText } = render(<UserCard user={mockUser} />)

    expect(getByText('John Doe')).toBeTruthy()
    expect(getByText('john@example.com')).toBeTruthy()
  })

  it('renders avatar when provided', () => {
    const { getByTestId } = render(<UserCard user={mockUser} />)

    const avatar = getByTestId('user-card-avatar')
    expect(avatar.props.source.uri).toBe('https://example.com/avatar.jpg')
  })

  it('calls onPress when pressed', () => {
    const onPress = jest.fn()
    const { getByTestId } = render(
      <UserCard user={mockUser} onPress={onPress} testID="user-card" />
    )

    fireEvent.press(getByTestId('user-card'))

    expect(onPress).toHaveBeenCalledWith('123')
  })

  it('does not crash without avatar', () => {
    const { getByTestId } = render(
      <UserCard user={{ ...mockUser, avatar: undefined }} />
    )

    expect(getByTestId('user-card-placeholder')).toBeTruthy()
  })
})
```

## Step 3: Run Tests - Verify FAIL

```bash
$ npm test UserCard

FAIL  src/components/UserCard.test.tsx
  UserCard
    × renders user name and email (5 ms)

    Error: Not implemented
```

Tests fail as expected!

## Step 4: Implement Minimal Code (GREEN)

```typescript
// src/components/UserCard.tsx
import React from 'react'
import { View, Text, Image, StyleSheet, TouchableOpacity } from 'react-native'
import FastImage from 'react-native-fast-image'

export interface UserCardProps {
  user: {
    id: string
    name: string
    email: string
    avatar?: string
  }
  onPress?: (userId: string) => void
  testID?: string
}

export function UserCard({ user, onPress, testID }: UserCardProps): React.JSX.Element {
  const handlePress = () => {
    onPress?.(user.id)
  }

  return (
    <TouchableOpacity
      testID={testID || 'user-card'}
      onPress={handlePress}
      style={styles.container}
    >
      {user.avatar ? (
        <FastImage
          testID="user-card-avatar"
          source={{ uri: user.avatar }}
          style={styles.avatar}
        />
      ) : (
        <View testID="user-card-placeholder" style={styles.placeholder} />
      )}
      <Text style={styles.name}>{user.name}</Text>
      <Text style={styles.email}>{user.email}</Text>
    </TouchableOpacity>
  )
}

const styles = StyleSheet.create({
  container: {
    padding: 16,
    backgroundColor: '#fff',
    borderRadius: 8,
  },
  avatar: {
    width: 50,
    height: 50,
    borderRadius: 25,
  },
  placeholder: {
    width: 50,
    height: 50,
    borderRadius: 25,
    backgroundColor: '#eee',
  },
  name: {
    fontSize: 16,
    fontWeight: '600',
  },
  email: {
    fontSize: 14,
    color: '#666',
  },
})
```

## Step 5: Run Tests - Verify PASS

```bash
$ npm test UserCard

PASS  src/components/UserCard.test.tsx
  UserCard
    ✓ renders user name and email (3 ms)
    ✓ renders avatar when provided (2 ms)
    ✓ calls onPress when pressed (1 ms)
    ✓ does not crash without avatar (1 ms)

Test Suites: 1 passed, 1 total
Tests:       4 passed, 4 total
```

All tests passing!

## Step 6: Check Coverage

```bash
$ npm test -- --coverage --collectCoverageFrom="src/components/UserCard.tsx"

----------|---------|----------|---------|---------|
File      | % Stmts | % Branch | % Funcs | % Lines |
----------|---------|----------|---------|---------|
UserCard  |   100   |   100    |   100   |   100   |
----------|---------|----------|---------|---------|

Coverage: 100%
```

## TDD Complete!
```

## Test Patterns

### Component Testing
```typescript
import { render, fireEvent } from '@testing-library/react-native'

// Basic render
const { getByTestId, getByText } = render(<MyComponent />)

// Fire events
fireEvent.press(getByTestId('button'))
fireEvent.changeText(getByTestId('input'), 'new text')

// Assertions with jest-native
import '@testing-library/jest-native'
expect(getByTestId('view')).toHaveStyle({ padding: 16 })
```

### Platform Testing
```typescript
// Mock Platform module
jest.mock('react-native/Libraries/Utilities/Platform', () => ({
  OS: 'ios',
  select: jest.fn((obj) => obj.ios),
}))

// Test platform-specific behavior
describe('iOS behavior', () => {
  beforeEach(() => {
    Platform.OS = 'ios'
  })

  it('renders iOS-specific component', () => {
    // Test iOS behavior
  })
})
```

### Navigation Testing
```typescript
import { NavigationContainer } from '@react-navigation/native'
import { render } from '@testing-library/react-native'

const mockNavigation = {
  navigate: jest.fn(),
  goBack: jest.fn(),
}

function renderWithNav(component) {
  return render(
    <NavigationContainer>
      {component}
    </NavigationContainer>
  )
}

it('navigates on button press', () => {
  const { getByTestId } = renderWithNav(
    <ProfileScreen navigation={mockNavigation} />
  )

  fireEvent.press(getByTestId('settings-button'))
  expect(mockNavigation.navigate).toHaveBeenCalledWith('Settings')
})
```

### Hook Testing
```typescript
import { renderHook, act } from '@testing-library/react-native'

it('manages state correctly', () => {
  const { result } = renderHook(() => useCustomHook())

  expect(result.current.value).toBe('initial')

  act(() => {
    result.current.setValue('new value')
  })

  expect(result.current.value).toBe('new value')
})
```

### Native Module Mocking
```typescript
// Mock AsyncStorage
jest.mock('@react-native-async-storage/async-storage', () =>
  require('@react-native-async-storage/async-storage/jest/async-storage-mock')
)

// Mock native modules
jest.mock('react-native/Libraries/Animated/NativeAnimatedHelper')

// Mock Platform
jest.mock('react-native/Libraries/Utilities/Platform')

// Mock custom native module
jest.mock('react-native-my-module', () => ({
  doSomethingNative: jest.fn(() => Promise.resolve('result')),
}))
```

## Coverage Commands

```bash
# Basic coverage
npm test -- --coverage

# Coverage for specific file
npm test -- UserCard --coverage --collectCoverageFrom="src/components/UserCard.tsx"

# Watch mode with coverage
npm test -- --watch --coverage

# Coverage with HTML report
npm test -- --coverage --coverageReporters="html"
open coverage/index.html
```

## Coverage Targets

| Code Type | Target |
|-----------|--------|
| Critical business logic | 90%+ |
| Components | 70%+ |
| Hooks | 80%+ |
| Navigation | 70%+ |
| Overall | 80%+ |

## TDD Best Practices

**DO:**
- Write test FIRST, before any implementation
- Use testID props for element selection
- Mock all native modules and Platform API
- Test user behavior, not implementation details
- Include edge cases (empty data, loading states, errors)
- Use jest-native for style assertions
- Test platform-specific code conditionally

**DON'T:**
- Write implementation before tests
- Skip the RED phase
- Test private functions directly
- Use `findBy` queries unnecessarily (prefer `getBy`)
- Test inline styles directly (use StyleSheet)
- Ignore platform differences in tests
- Use `setTimeout` in tests (use fake timers)

## Example Setup Files

### jest.setup.js
```javascript
import '@testing-library/jest-native/extend-expect'

// Mock native modules
jest.mock('react-native/Libraries/Animated/NativeAnimatedHelper')
jest.mock('react-native/Libraries/Utilities/Platform')

// Mock AsyncStorage
jest.mock('@react-native-async-storage/async-storage', () =>
  require('@react-native-async-storage/async-storage/jest/async-storage-mock')
)
```

### jest.config.js
```javascript
module.exports = {
  preset: 'react-native',
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  transformIgnorePatterns: [
    'node_modules/(?!(react-native|@react-native|@react-navigation)/)',
  ],
  testMatch: ['**/__tests__/**/*.test.(ts|tsx|js)'],
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.stories.tsx',
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
}
```

## Related Commands

- `/rn-build` - Fix build errors
- `/rn-review` - Review code after implementation
- `/tdd` - General TDD workflow

## Related

- Skill: `skills/react-native-patterns/`
- Skill: `skills/tdd-workflow/`
- Agent: `agents/rn-reviewer.md`
