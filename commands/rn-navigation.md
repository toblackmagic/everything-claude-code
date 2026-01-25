---
name: rn-navigation
description: Set up React Navigation with type safety, deep linking, and best practices
---

# /rn-navigation

Set up React Navigation with proper TypeScript types, deep linking, and authentication flow.

## Usage

```
/rn-navigation [options]
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--type` | Navigation type: stack, tab, drawer, auth | stack |
| `--deep-link` | Enable deep linking | true |
| `--auth` | Include authentication flow | false |
| `--bottom-tabs` | Add bottom tab navigator | false |
| `--typescript` | Generate TypeScript files | true |

## Examples

```bash
# Basic stack navigator
/rn-navigation --type stack

# Full navigation with auth and tabs
/rn-navigation --auth --bottom-tabs --deep-link

# Tab navigator only
/rn-navigation --type tab
```

## What Gets Created

### Basic Stack Navigator

```
src/navigation/
├── types.ts              # Navigation type definitions
├── RootNavigator.tsx     # Root navigation container
└── AppNavigator.tsx      # Main app stack navigator
```

### With Auth Flow

```
src/navigation/
├── types.ts
├── RootNavigator.tsx     # Handles auth/app switching
├── AuthNavigator.tsx     # Login, register, forgot password
└── AppNavigator.tsx      # Main app after auth
```

### With Bottom Tabs

```
src/navigation/
├── types.ts
├── RootNavigator.tsx
├── AppNavigator.tsx
└── MainTabNavigator.tsx  # Bottom tab navigation
```

## Generated Templates

### Type Definitions (types.ts)

```typescript
import type {
  NavigatorScreenParams,
  NavigationState,
  PartialState,
} from '@react-navigation/native'
import type { NativeStackScreenProps } from '@react-navigation/native-stack'

// Auth stack
export type AuthStackParamList = {
  Login: undefined
  Register: { email?: string }
  ForgotPassword: undefined
}

// App stack
export type AppStackParamList = {
  Home: undefined
  Profile: { userId: string }
  Settings: undefined
  PostDetails: { postId: string }
}

// Tab navigator
export type MainTabParamList = {
  HomeTab: undefined
  SearchTab: undefined
  ProfileTab: undefined
}

// Root navigator
export type RootStackParamList = {
  Auth: NavigatorScreenParams<AuthStackParamList>
  App: NavigatorScreenParams<AppStackParamList>
}

// Type helpers
export type AuthStackScreenProps<T extends keyof AuthStackParamList> =
  NativeStackScreenProps<AuthStackParamList, T>

export type AppStackScreenProps<T extends keyof AppStackParamList> =
  NativeStackScreenProps<AppStackParamList, T>

export type MainTabScreenProps<T extends keyof MainTabParamList> =
  NativeStackScreenProps<MainTabParamList, T>
```

### Auth Navigator (AuthNavigator.tsx)

```typescript
import { createNativeStackNavigator } from '@react-navigation/native-stack'
import type { AuthStackParamList } from './types'
import { LoginScreen } from '@/screens/auth/LoginScreen'
import { RegisterScreen } from '@/screens/auth/RegisterScreen'
import { ForgotPasswordScreen } from '@/screens/auth/ForgotPasswordScreen'

const Stack = createNativeStackNavigator<AuthStackParamList>()

export function AuthNavigator() {
  return (
    <Stack.Navigator
      initialRouteName="Login"
      screenOptions={{
        headerShown: false,
        animation: 'slide_from_right',
        orientation: 'portrait',
      }}
    >
      <Stack.Screen name="Login" component={LoginScreen} />
      <Stack.Screen name="Register" component={RegisterScreen} />
      <Stack.Screen
        name="ForgotPassword"
        component={ForgotPasswordScreen}
        options={{ presentation: 'modal' }}
      />
    </Stack.Navigator>
  )
}
```

### App Navigator (AppNavigator.tsx)

```typescript
import { createNativeStackNavigator } from '@react-navigation/native-stack'
import type { AppStackParamList } from './types'
import { HomeScreen } from '@/screens/home/HomeScreen'
import { ProfileScreen } from '@/screens/profile/ProfileScreen'
import { SettingsScreen } from '@/screens/settings/SettingsScreen'

const Stack = createNativeStackNavigator<AppStackParamList>()

export function AppNavigator() {
  return (
    <Stack.Navigator
      initialRouteName="Home"
      screenOptions={{
        headerShown: true,
        headerBackTitleVisible: false,
        headerTintColor: '#007AFF',
      }}
    >
      <Stack.Screen
        name="Home"
        component={HomeScreen}
        options={{ title: 'Home' }}
      />
      <Stack.Screen
        name="Profile"
        component={ProfileScreen}
        options={({ route }) => ({
          title: `Profile: ${route.params.userId}`,
        })}
      />
      <Stack.Screen
        name="Settings"
        component={SettingsScreen}
        options={{ presentation: 'modal' }}
      />
    </Stack.Navigator>
  )
}
```

### Main Tab Navigator (MainTabNavigator.tsx)

```typescript
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs'
import type { MainTabParamList } from './types'
import { HomeIcon, SearchIcon, ProfileIcon } from '@/components/icons'

import { HomeScreen } from '@/screens/home/HomeScreen'
import { SearchScreen } from '@/screens/search/SearchScreen'
import { ProfileScreen } from '@/screens/profile/ProfileScreen'

const Tab = createBottomTabNavigator<MainTabParamList>()

export function MainTabNavigator() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        headerShown: false,
        tabBarIcon: ({ focused, color }) => {
          switch (route.name) {
            case 'HomeTab':
              return <HomeIcon focused={focused} color={color} />
            case 'SearchTab':
              return <SearchIcon focused={focused} color={color} />
            case 'ProfileTab':
              return <ProfileIcon focused={focused} color={color} />
          }
        },
        tabBarActiveTintColor: '#007AFF',
        tabBarInactiveTintColor: '#999',
        tabBarStyle: {
          height: 60,
          paddingBottom: 8,
          paddingTop: 8,
        },
      })}
    >
      <Tab.Screen
        name="HomeTab"
        component={HomeScreen}
        options={{ tabBarLabel: 'Home' }}
      />
      <Tab.Screen
        name="SearchTab"
        component={SearchScreen}
        options={{ tabBarLabel: 'Search' }}
      />
      <Tab.Screen
        name="ProfileTab"
        component={ProfileScreen}
        options={{ tabBarLabel: 'Profile' }}
      />
    </Tab.Navigator>
  )
}
```

### Root Navigator (RootNavigator.tsx)

```typescript
import { createNativeStackNavigator } from '@react-navigation/native-stack'
import type { RootStackParamList } from './types'
import { useAuth } from '@/hooks/useAuth'
import { AuthNavigator } from './AuthNavigator'
import { AppNavigator } from './AppNavigator'

const Stack = createNativeStackNavigator<RootStackParamList>()

export function RootNavigator() {
  const { isAuthenticated } = useAuth()

  return (
    <Stack.Navigator
      screenOptions={{
        headerShown: false,
      }}
    >
      {!isAuthenticated ? (
        <Stack.Screen name="Auth" component={AuthNavigator} />
      ) : (
        <Stack.Screen name="App" component={AppNavigator} />
      )}
    </Stack.Navigator>
  )
}
```

### Deep Linking Configuration

```typescript
// src/navigation/linking.ts
import type { RootStackParamList } from './types'

const linking = {
  prefixes: ['myapp://', 'https://myapp.com'],
  config: {
    screens: {
      Auth: {
        screens: {
          Login: 'login',
          Register: 'register',
        },
      },
      App: {
        screens: {
          Home: '',
          Profile: {
            path: 'profile/:userId',
            parse: {
              userId: (userId: string) => userId,
            },
          },
          PostDetails: 'post/:postId',
        },
      },
    },
  },
}

export default linking
```

### Navigation Container Setup

```typescript
// src/navigation/index.tsx
import { NavigationContainer } from '@react-navigation/native'
import { useRef } from 'react'
import type { RootStackParamList } from './types'
import { RootNavigator } from './RootNavigator'
import linking from './linking'

export function Navigation() {
  const navigationRef = useRef<NavigationContainerRef<RootStackParamList>>(null)

  return (
    <NavigationContainer
      ref={navigationRef}
      linking={linking}
      fallback={<LoadingScreen />}
      onReady={() => {
        // Navigation is ready
      }}
    >
      <RootNavigator />
    </NavigationContainer>
  )
}
```

## Custom Hooks

### useTypedNavigation Hook

```typescript
// src/hooks/useTypedNavigation.ts
import { useNavigation } from '@react-navigation/native'
import type { NativeStackNavigationProp } from '@react-navigation/native-stack'
import type { RootStackParamList } from '@/navigation/types'

export type AppNavigationProp =
  NativeStackNavigationProp<RootStackParamList>

export function useTypedNavigation(): AppNavigationProp {
  return useNavigation<AppNavigationProp>()
}
```

## Navigation Actions

```typescript
// Usage examples
import { useTypedNavigation } from '@/hooks/useTypedNavigation'

function MyComponent() {
  const navigation = useTypedNavigation()

  // Navigate to screen
  const goToProfile = (userId: string) => {
    navigation.navigate('App', {
      screen: 'Profile',
      params: { userId },
    })
  }

  // Go back
  const goBack = () => {
    navigation.goBack()
  }

  // Reset navigation
  const resetToHome = () => {
    navigation.reset({
      index: 0,
      routes: [{ name: 'App', params: { screen: 'Home' } }],
    })
  }

  return <View>...</View>
}
```

## Installation

The command will automatically install:

```bash
npm install @react-navigation/native
npm install react-native-screens react-native-safe-area-context

# For stack navigation
npm install @react-navigation/native-stack

# For tabs (if --bottom-tabs)
npm install @react-navigation/bottom-tabs

# For deep linking (if --deep-link)
npm install expo-linking
```

---

**Tip**: Always define your navigation types first. This ensures type safety throughout your app and catches navigation errors at compile time.
