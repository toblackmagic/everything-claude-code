# React Native Testing

Comprehensive testing strategies and patterns for React Native applications.

## Testing Stack

### Recommended Libraries

```bash
# Core testing library
npm install --save-dev @testing-library/react-native

# Jest configuration
npm install --save-dev jest @testing-library/jest-native

# TypeScript types
npm install --save-dev @types/jest

# Test utilities
npm install --save-dev react-test-renderer

# Mock for native modules
npm install --save-dev react-native-mock-bridge

# Network mocking
npm install --save-dev nock

# Navigation testing
npm install --save-dev @react-navigation/native
```

### Jest Configuration

```javascript
// jest.config.js
module.exports = {
  preset: 'react-native',
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  testMatch: ['**/__tests__/**/*.test.[jt]s?(x)', '**/?(*.)+(spec|test).[jt]s?(x)'],
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
  ],
  moduleNameMapper: {
    '\\.(jpg|jpeg|png|gif|svg)$': '<rootDir>/__mocks__/imageMock.js',
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  transformIgnorePatterns: [
    'node_modules/(?!(react-native|@react-native|@react-navigation|@react-native-community|expo-modules-core))',
  ],
}
```

```javascript
// jest.setup.js
import '@testing-library/jest-native/extend-expect'

// Mock native modules
jest.mock('react-native/Libraries/Animated/NativeAnimatedHelper')

// Mock AsyncStorage
jest.mock('@react-native-async-storage/async-storage', () =>
  require('@react-native-async-storage/async-storage/jest/async-storage-mock')
)

// Mock navigation
jest.mock('@react-navigation/native', () => ({
  ...jest.requireActual('@react-navigation/native'),
  useNavigation: () => ({
    navigate: jest.fn(),
    goBack: jest.fn(),
    reset: jest.fn(),
  }),
  useRoute: () => ({
    params: {},
  }),
}))
```

## Component Testing

### Basic Component Test

```typescript
// __tests__/components/Button.test.tsx
import React from 'react'
import { render, fireEvent } from '@testing-library/react-native'
import { Button } from '@/components/Button'

describe('Button', () => {
  it('renders title correctly', () => {
    const { getByText } = render(<Button title="Click me" onPress={() => {}} />)
    expect(getByText('Click me')).toBeTruthy()
  })

  it('calls onPress when pressed', () => {
    const onPress = jest.fn()
    const { getByText } = render(
      <Button title="Click me" onPress={onPress} />
    )

    fireEvent.press(getByText('Click me'))
    expect(onPress).toHaveBeenCalledTimes(1)
  })

  it('does not call onPress when disabled', () => {
    const onPress = jest.fn()
    const { getByText } = render(
      <Button title="Click me" onPress={onPress} disabled />
    )

    fireEvent.press(getByText('Click me'))
    expect(onPress).not.toHaveBeenCalled()
  })

  it('applies correct variant styles', () => {
    const { getByTestId } = render(
      <Button title="Test" onPress={() => {}} variant="outline" testID="button" />
    )

    expect(getByTestId('button')).toHaveStyle({
      borderWidth: 2,
      borderColor: '#007AFF',
    })
  })
})
```

### Testing Hooks

```typescript
// __tests__/hooks/useToggle.test.ts
import { renderHook, act } from '@testing-library/react-native'
import { useToggle } from '@/hooks/useToggle'

describe('useToggle', () => {
  it('initializes with default value', () => {
    const { result } = renderHook(() => useToggle())
    expect(result.current[0]).toBe(false)
  })

  it('toggles value', () => {
    const { result } = renderHook(() => useToggle(true))

    act(() => {
      result.current[1]()
    })

    expect(result.current[0]).toBe(false)
  })
})
```

### Testing Platform-Specific Code

```typescript
// __tests__/components/PlatformAware.test.tsx
import React from 'react'
import { render } from '@testing-library/react-native'
import { PlatformAwareComponent } from '@/components/PlatformAwareComponent'

// Mock Platform module
jest.mock('react-native', () => {
  const RN = jest.requireActual('react-native')
  RN.Platform = {
    OS: 'ios',
    Version: 13,
    select: jest.fn((obj) => obj.ios),
  }
  return RN
})

describe('PlatformAwareComponent', () => {
  it('renders iOS components on iOS', () => {
    const { getByText } = render(<PlatformAwareComponent />)
    expect(getByText('iOS Component')).toBeTruthy()
  })
})

// Reset for Android tests
describe('PlatformAwareComponent (Android)', () => {
  beforeEach(() => {
    const Platform = require('react-native').Platform
    Platform.OS = 'android'
  })

  it('renders Android components on Android', () => {
    const { getByText } = render(<PlatformAwareComponent />)
    expect(getByText('Android Component')).toBeTruthy()
  })
})
```

## Navigation Testing

### Testing Navigation Actions

```typescript
// __tests__/navigation/ProfileScreen.test.tsx
import React from 'react'
import { render, fireEvent } from '@testing-library/react-native'
import { ProfileScreen } from '@/screens/ProfileScreen'
import { NavigationContainer } from '@react-navigation/native'

const mockNavigation = {
  navigate: jest.fn(),
  goBack: jest.fn(),
  reset: jest.fn(),
}

const mockRoute = {
  params: {
    userId: '123',
  },
}

function renderWithNav(component: React.ReactElement) {
  return render(
    <NavigationContainer>
      {component}
    </NavigationContainer>
  )
}

describe('ProfileScreen', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('renders user profile', () => {
    const { getByText } = renderWithNav(
      <ProfileScreen navigation={mockNavigation} route={mockRoute} />
    )

    expect(getByText('Profile: 123')).toBeTruthy()
  })

  it('navigates to settings on button press', () => {
    const { getByText } = renderWithNav(
      <ProfileScreen navigation={mockNavigation} route={mockRoute} />
    )

    fireEvent.press(getByText('Settings'))
    expect(mockNavigation.navigate).toHaveBeenCalledWith('Settings')
  })
})
```

### Testing Deep Links

```typescript
// __tests__/navigation/deepLink.test.ts
import { navigationRef } from '@/navigation/NavigationContainer'
import * as Linking from 'expo-linking'

describe('Deep Linking', () => {
  it('navigates to profile with correct params', async () => {
    const url = 'myapp://profile/123'

    await Linking.parseURL(url)

    expect(navigationRef.current?.getCurrentRoute()?.name).toBe('Profile')
    expect(navigationRef.current?.getCurrentRoute()?.params).toEqual({
      userId: '123',
    })
  })
})
```

## Testing Native Modules

### Mocking Native Modules

```typescript
// __mocks__/NativeModule.ts
import { NativeModules } from 'react-native'

export default {
  multiply: jest.fn((a: number, b: number) => Promise.resolve(a * b)),
  addListener: jest.fn(),
  removeListeners: jest.fn(),
}

// Register the mock
NativeModules.NativeModule = mockDefault
```

```typescript
// __tests__/native/NativeModule.test.ts
import NativeModule from '@/NativeModule'

describe('NativeModule', () => {
  it('multiplies numbers correctly', async () => {
    const result = await NativeModule.multiply(5, 3)
    expect(result).toBe(15)
  })

  it('handles errors', async () => {
    (NativeModule.multiply as jest.Mock).mockRejectedValueOnce(
      new Error('Multiplication failed')
    )

    await expect(NativeModule.multiply(1, 2)).rejects.toThrow('Multiplication failed')
  })
})
```

## Integration Testing

### Testing Full User Flows

```typescript
// __tests__/flows/loginFlow.test.tsx
import React from 'react'
import { render, fireEvent, waitFor } from '@testing-library/react-native'
import { App } from '@/App'

describe('Login Flow', () => {
  it('logs in user and navigates to home', async () => {
    const { getByPlaceholderText, getByText } = render(<App />)

    // Enter credentials
    fireEvent.changeText(
      getByPlaceholderText('Email'),
      'test@example.com'
    )
    fireEvent.changeText(
      getByPlaceholderText('Password'),
      'password123'
    )

    // Press login
    fireEvent.press(getByText('Login'))

    // Wait for navigation
    await waitFor(() => {
      expect(getByText('Welcome')).toBeTruthy()
    })
  })
})
```

## Testing List Components

### Testing FlatList

```typescript
// __tests__/components/UserList.test.tsx
import React from 'react'
import { render, waitFor } from '@testing-library/react-native'
import { UserList } from '@/components/UserList'

const mockUsers = [
  { id: '1', name: 'Alice' },
  { id: '2', name: 'Bob' },
  { id: '3', name: 'Charlie' },
]

describe('UserList', () => {
  it('renders all users', async () => {
    const { getByText } = render(
      <UserList users={mockUsers} onPress={() => {}} />
    )

    await waitFor(() => {
      expect(getByText('Alice')).toBeTruthy()
      expect(getByText('Bob')).toBeTruthy()
      expect(getByText('Charlie')).toBeTruthy()
    })
  })

  it('calls onPress with correct user', async () => {
    const onPress = jest.fn()
    const { getByText } = render(
      <UserList users={mockUsers} onPress={onPress} />
    )

    fireEvent.press(getByText('Alice'))
    expect(onPress).toHaveBeenCalledWith(mockUsers[0])
  })
})
```

## E2E Testing with Detox

### Detox Setup

```bash
npm install --save-dev detox
npx detox init
```

```javascript
// detox.config.js
module.exports = {
  testRunner: {
    args: {
      '$0': 'jest',
      config: 'e2e/jest.config.js'
    },
    jest: {
      setupTimeout: 120000,
    },
  },
  apps: {
    'ios.debug': {
      type: 'ios.app',
      binaryPath: 'ios/build/Build/Products/Debug-iphonesimulator/MyApp.app',
      build: 'xcodebuild -workspace ios/MyApp.xcworkspace -scheme MyApp -configuration Debug -sdk iphonesimulator -derivedDataPath ios/build',
    },
    'android.debug': {
      type: 'android.apk',
      binaryPath: 'android/app/build/outputs/apk/debug/app-debug.apk',
      build: 'cd android && ./gradlew assembleDebug assembleAndroidTest -DtestBuildType=debug && cd ..',
    },
  },
  devices: {
    simulator: {
      type: 'ios.simulator',
      device: { type: 'iPhone 14' },
    },
    emulator: {
      type: 'android.emulator',
      device: { avdName: 'Pixel_5_API_31' },
    },
  },
  configurations: {
    'ios.sim.debug': {
      device: 'simulator',
      app: 'ios.debug',
    },
    'android.emu.debug': {
      device: 'emulator',
      app: 'android.debug',
    },
  },
}
```

### Detox Test Example

```typescript
// e2e/login.e2e.ts
describe('Login', () => {
  beforeAll(async () => {
    await device.launchApp()
  })

  beforeEach(async () => {
    await device.reloadReactNative()
  })

  it('should login successfully', async () => {
    await element(by.id('email-input')).typeText('test@example.com')
    await element(by.id('password-input')).typeText('password123')
    await element(by.id('login-button')).tap()

    await expect(element(by.text('Welcome'))).toBeVisible()
  })
})
```

## Testing Best Practices

### Do's
- ✅ Test user behavior, not implementation details
- ✅ Use `testID` props for finding elements
- ✅ Mock external dependencies (API, native modules)
- ✅ Test both success and error cases
- ✅ Keep tests simple and focused
- ✅ Use descriptive test names

### Don'ts
- ❌ Test internal state or methods
- ❌ Over-mock (test real behavior when possible)
- ❌ Test third-party libraries
- ❌ Make tests dependent on each other
- ❌ Write brittle selectors (use testID instead)

### Test Coverage Goals

| Type | Coverage Target |
|------|-----------------|
| Critical business logic | 90%+ |
| UI components | 70%+ |
| Utilities/Hooks | 80%+ |
| Overall | 70%+ |

### Running Tests

```bash
# Unit tests
npm test

# Watch mode
npm test -- --watch

# Coverage
npm test -- --coverage

# Specific file
npm test -- Button.test.tsx

# E2E tests
npx detox test

# Build for E2E
npx detox build --configuration ios.sim.debug
```

---

**Remember**: Tests are code too. Keep them clean, maintainable, and focused on what matters: ensuring your app works correctly for users.
