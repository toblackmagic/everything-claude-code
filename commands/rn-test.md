---
name: rn-test
description: Set up testing infrastructure for React Native with Jest, React Native Testing Library, and Detox
---

# /rn-test

Set up complete testing infrastructure for React Native applications.

## Usage

```
/rn-test [options]
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--e2e` | Include Detox for E2E testing | false |
| `--coverage` | Set coverage thresholds | true |
| `--typescript` | Generate TypeScript test files | true |
| `--snapshots` | Enable snapshot testing | true |

## Examples

```bash
# Basic testing setup
/rn-test

# Full testing with E2E
/rn-test --e2e --coverage

# Setup with specific options
/rn-test --coverage --snapshots
```

## What Gets Created

### Test Configuration

```
├── jest.config.js
├── jest.setup.js
├── .jest/
│   └── imageMock.js
├── __mocks__/
│   ├── react-native.config.js
│   └── @react-navigation/
├── __tests__/
│   ├── components/
│   ├── hooks/
│   └── navigation/
└── e2e/
    ├── detox.config.js
    ├── jest.config.js
    └── scenarios/
```

## Generated Files

### jest.config.js

```javascript
module.exports = {
  preset: 'react-native',
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  testMatch: [
    '**/__tests__/**/*.test.[jt]s?(x)',
    '**/?(*.)+(spec|test).[jt]s?(x)'
  ],
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
    '!src/**/{index,constants}.{js,ts}',
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70,
    },
  },
  moduleNameMapper: {
    '\\.(jpg|jpeg|png|gif|svg)$': '<rootDir>/.jest/imageMock.js',
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@components/(.*)$': '<rootDir>/src/components/$1',
    '^@screens/(.*)$': '<rootDir>/src/screens/$1',
    '^@navigation/(.*)$': '<rootDir>/src/navigation/$1',
    '^@hooks/(.*)$': '<rootDir>/src/hooks/$1',
    '^@services/(.*)$': '<rootDir>/src/services/$1',
    '^@utils/(.*)$': '<rootDir>/src/utils/$1',
  },
  transformIgnorePatterns: [
    'node_modules/(?!(react-native|@react-native|@react-navigation|@react-native-community|expo-modules-core|@expo|expo|@expo-google-fonts))',
  ],
}
```

### jest.setup.js

```javascript
import '@testing-library/jest-native/extend-expect'

// Mock Animated API
jest.mock('react-native/Libraries/Animated/NativeAnimatedHelper')

// Mock AsyncStorage
jest.mock('@react-native-async-storage/async-storage', () =>
  require('@react-native-async-storage/async-storage/jest/async-storage-mock')
)

// Mock react-native-safe-area-context
jest.mock('react-native-safe-area-context', () => {
  const inset = { top: 0, right: 0, bottom: 0, left: 0 }
  return {
    SafeAreaProvider: ({ children }) => children,
    SafeAreaContext: {
      Consumer: ({ children }) => children(inset),
      Provider: ({ children }) => children,
    },
    useSafeAreaInsets: () => inset,
    useSafeAreaFrame: () => ({ x: 0, y: 0, width: 375, height: 812 }),
  }
})

// Mock Navigation
jest.mock('@react-navigation/native', () => {
  const actualNav = jest.requireActual('@react-navigation/native')
  return {
    ...actualNav,
    useNavigation: () => ({
      navigate: jest.fn(),
      goBack: jest.fn(),
      reset: jest.fn(),
      setParams: jest.fn(),
      dispatch: jest.fn(),
      canGoBack: jest.fn(() => true),
      isFocused: jest.fn(() => true),
    }),
    useRoute: () => ({
      params: {},
      name: 'TestScreen',
      path: undefined,
    }),
    useFocusEffect: jest.fn((effect) => effect()),
    useIsFocused: jest.fn(() => true),
  }
})

// Mock Expo modules
jest.mock('expo-constants', () => ({
  default: { expoConfig: { extra: {} } },
}))

jest.mock('expo-linking', () => ({
  createURL: jest.fn(),
  openURL: jest.fn(),
  openAuthRequestAsync: jest.fn(),
}))

// Silence console.warn in tests
global.console = {
  ...console,
  warn: jest.fn(),
  error: jest.fn(),
}

// Mock Platform
jest.mock('react-native/Libraries/Utilities/Platform', () => ({
  OS: 'ios',
  Version: 13,
  select: (obj) => obj.ios,
}))
```

### .jest/imageMock.js

```javascript
module.exports = 'test-image-stub'
```

## Test Templates

### Component Test Template

```typescript
// __tests__/components/Button.test.tsx
import React from 'react'
import { render, fireEvent } from '@testing-library/react-native'
import { Button } from '@/components/Button'

describe('Button', () => {
  const defaultProps = {
    title: 'Test Button',
    onPress: jest.fn(),
  }

  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('renders correctly', () => {
    const { getByText } = render(<Button {...defaultProps} />)
    expect(getByText('Test Button')).toBeTruthy()
  })

  it('calls onPress when pressed', () => {
    const onPress = jest.fn()
    const { getByText } = render(<Button {...defaultProps} onPress={onPress} />)

    fireEvent.press(getByText('Test Button'))
    expect(onPress).toHaveBeenCalledTimes(1)
  })

  it('does not call onPress when disabled', () => {
    const onPress = jest.fn()
    const { getByText } = render(
      <Button {...defaultProps} onPress={onPress} disabled />
    )

    fireEvent.press(getByText('Test Button'))
    expect(onPress).not.toHaveBeenCalled()
  })

  describe('variants', () => {
    it('applies primary variant styles', () => {
      const { getByTestId } = render(
        <Button {...defaultProps} variant="primary" testID="button" />
      )
      expect(getByTestId('button')).toHaveStyle({ backgroundColor: '#007AFF' })
    })

    it('applies outline variant styles', () => {
      const { getByTestId } = render(
        <Button {...defaultProps} variant="outline" testID="button" />
      )
      expect(getByTestId('button')).toHaveStyle({
        borderWidth: 2,
        borderColor: '#007AFF',
      })
    })
  })
})
```

### Hook Test Template

```typescript
// __tests__/hooks/useToggle.test.ts
import { renderHook, act } from '@testing-library/react-native'
import { useToggle } from '@/hooks/useToggle'

describe('useToggle', () => {
  it('initializes with default value', () => {
    const { result } = renderHook(() => useToggle())
    expect(result.current[0]).toBe(false)
  })

  it('initializes with custom value', () => {
    const { result } = renderHook(() => useToggle(true))
    expect(result.current[0]).toBe(true)
  })

  it('toggles value', () => {
    const { result } = renderHook(() => useToggle())

    act(() => {
      result.current[1]()
    })

    expect(result.current[0]).toBe(true)
  })

  it('toggles back and forth', () => {
    const { result } = renderHook(() => useToggle())

    act(() => {
      result.current[1]()
    })
    expect(result.current[0]).toBe(true)

    act(() => {
      result.current[1]()
    })
    expect(result.current[0]).toBe(false)
  })
})
```

### Screen Test Template

```typescript
// __tests__/screens/HomeScreen.test.tsx
import React from 'react'
import { render, fireEvent } from '@testing-library/react-native'
import { HomeScreen } from '@/screens/HomeScreen'

const mockNavigation = {
  navigate: jest.fn(),
  goBack: jest.fn(),
  reset: jest.fn(),
}

const mockRoute = {
  params: {},
}

describe('HomeScreen', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('renders correctly', () => {
    const { getByText } = render(
      <HomeScreen navigation={mockNavigation} route={mockRoute} />
    )
    expect(getByText('Home')).toBeTruthy()
  })

  it('navigates to profile on button press', () => {
    const { getByText } = render(
      <HomeScreen navigation={mockNavigation} route={mockRoute} />
    )

    fireEvent.press(getByText('Go to Profile'))
    expect(mockNavigation.navigate).toHaveBeenCalledWith('Profile', {
      userId: expect.any(String),
    })
  })
})
```

## Detox Configuration (with --e2e)

### detox.config.js

```javascript
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

### E2E Test Example

```typescript
// e2e/login.e2e.ts
describe('Login Flow', () => {
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

  it('should show error for invalid credentials', async () => {
    await element(by.id('email-input')).typeText('invalid@example.com')
    await element(by.id('password-input')).typeText('wrongpassword')
    await element(by.id('login-button')).tap()

    await expect(element(by.text('Invalid credentials'))).toBeVisible()
  })
})
```

## Package.json Scripts

```json
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:ci": "jest --ci --coverage --maxWorkers=2",
    "test:update": "jest --updateSnapshot",
    "detox:test": "detox test",
    "detox:build": "detox build --configuration ios.sim.debug"
  }
}
```

## Installation

The command will install:

```bash
# Core testing
npm install --save-dev @testing-library/react-native @testing-library/jest-native jest

# TypeScript
npm install --save-dev @types/jest

# React test renderer
npm install --save-dev react-test-renderer

# AsyncStorage mock
npm install --save-dev @react-native-async-storage/async-storage/jest/async-storage-mock

# E2E testing (with --e2e)
npm install --save-dev detox
```

## Testing Best Practices

1. **Test behavior, not implementation**
2. **Use `testID` props for element selection**
3. **Mock external dependencies**
4. **Keep tests focused and simple**
5. **Test both success and error cases**
6. **A brittle selector:** `className="button"` → `testID="submit-button"`
7. **Keep tests independent**

---

**Remember**: Tests are documentation. Good tests describe how your components should work and serve as examples for other developers.
