# React Native Navigation Patterns

Comprehensive navigation patterns using React Navigation for React Native applications.

## Installation

```bash
npm install @react-navigation/native
npm install react-native-screens react-native-safe-area-context

# For stack navigation
npm install @react-navigation/native-stack

# For bottom tabs
npm install @react-navigation/bottom-tabs

# For drawer navigation
npm install @react-navigation/drawer

# For top tabs
npm install @react-navigation/top-tabs
npm install react-native-pager-view react-native-tab-view

# For linking
npm install @react-navigation/links
```

## Project Structure

```
src/
├── navigation/
│   ├── index.tsx           # Navigation container
│   ├── RootNavigator.tsx   # Root navigation
│   ├── AuthNavigator.tsx   # Auth flow
│   ├── AppNavigator.tsx    # Main app flow
│   └── types.ts            # Navigation types
├── screens/
│   ├── auth/
│   │   ├── LoginScreen.tsx
│   │   └── RegisterScreen.tsx
│   ├── home/
│   │   └── HomeScreen.tsx
│   └── profile/
│       └── ProfileScreen.tsx
```

## Type-Safe Navigation

### Navigation Types Definition

```typescript
// src/navigation/types.ts
import type {
  NavigationContainerProps,
  NavigatorScreenParams,
} from '@react-navigation/native'
import type { NativeStackScreenProps } from '@react-navigation/native-stack'

// Auth stack params
export type AuthStackParamList = {
  Login: undefined
  Register: { email?: string }
  ForgotPassword: { email?: string }
}

// App stack params
export type AppStackParamList = {
  Home: undefined
  Profile: { userId: string }
  Settings: undefined
  PostDetails: { postId: string }
}

// Root params
export type RootStackParamList = {
  Auth: NavigatorScreenParams<AuthStackParamList>
  App: NavigatorScreenParams<AppStackParamList>
}

// Tab params
export type MainTabParamList = {
  Home: undefined
  Search: undefined
  Profile: { userId: string }
  Notifications: undefined
}

// Type helpers
export type AuthStackScreenProps<T extends keyof AuthStackParamList> =
  NativeStackScreenProps<AuthStackParamList, T>

export type AppStackScreenProps<T extends keyof AppStackParamList> =
  NativeStackScreenProps<AppStackParamList, T>

export type MainTabScreenProps<T extends keyof MainTabParamList> =
  NativeStackScreenProps<MainTabParamList, T>
```

## Authentication Flow

### Auth Navigator

```typescript
// src/navigation/AuthNavigator.tsx
import { createNativeStackNavigator } from '@react-navigation/native-stack'
import type { AuthStackParamList } from './types'

import LoginScreen from '@/screens/auth/LoginScreen'
import RegisterScreen from '@/screens/auth/RegisterScreen'
import ForgotPasswordScreen from '@/screens/auth/ForgotPasswordScreen'

const Stack = createNativeStackNavigator<AuthStackParamList>()

export function AuthNavigator() {
  return (
    <Stack.Navigator
      initialRouteName="Login"
      screenOptions={{
        headerShown: false,
        animation: 'slide_from_right',
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

### App Navigator

```typescript
// src/navigation/AppNavigator.tsx
import { createNativeStackNavigator } from '@react-navigation/native-stack'
import type { AppStackParamList } from './types'

import HomeScreen from '@/screens/home/HomeScreen'
import ProfileScreen from '@/screens/profile/ProfileScreen'
import SettingsScreen from '@/screens/settings/SettingsScreen'
import PostDetailsScreen from '@/screens/posts/PostDetailsScreen'

const Stack = createNativeStackNavigator<AppStackParamList>()

export function AppNavigator() {
  return (
    <Stack.Navigator
      initialRouteName="Home"
      screenOptions={{
        headerShown: true,
        headerBackTitleVisible: false,
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
        options={({ route }) => ({ title: `Profile: ${route.params.userId}` })}
      />
      <Stack.Screen
        name="Settings"
        component={SettingsScreen}
        options={{ presentation: 'modal' }}
      />
      <Stack.Screen
        name="PostDetails"
        component={PostDetailsScreen}
        options={({ route }) => ({ title: `Post ${route.params.postId}` })}
      />
    </Stack.Navigator>
  )
}
```

### Root Navigator with Auth

```typescript
// src/navigation/RootNavigator.tsx
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

## Tab Navigation

### Bottom Tabs Navigator

```typescript
// src/navigation/MainTabNavigator.tsx
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs'
import type { MainTabParamList } from './types'

import HomeScreen from '@/screens/home/HomeScreen'
import SearchScreen from '@/screens/search/SearchScreen'
import ProfileScreen from '@/screens/profile/ProfileScreen'
import NotificationsScreen from '@/screens/notifications/NotificationsScreen'

import { HomeIcon, SearchIcon, ProfileIcon, BellIcon } from '@/components/icons'

const Tab = createBottomTabNavigator<MainTabParamList>()

function TabBarIcon({ name, focused }: { name: string; focused: boolean }) {
  switch (name) {
    case 'Home':
      return <HomeIcon focused={focused} />
    case 'Search':
      return <SearchIcon focused={focused} />
    case 'Profile':
      return <ProfileIcon focused={focused} />
    case 'Notifications':
      return <BellIcon focused={focused} />
    default:
      return null
  }
}

export function MainTabNavigator() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        headerShown: false,
        tabBarIcon: ({ focused }) => (
          <TabBarIcon name={route.name} focused={focused} />
        ),
        tabBarActiveTintColor: '#007AFF',
        tabBarInactiveTintColor: '#999',
        tabBarStyle: {
          height: 60,
          paddingBottom: 8,
          paddingTop: 8,
        },
        tabBarLabelStyle: {
          fontSize: 12,
          fontWeight: '600',
        },
      })}
    >
      <Tab.Screen
        name="Home"
        component={HomeScreen}
        options={{ tabBarLabel: 'Home' }}
      />
      <Tab.Screen
        name="Search"
        component={SearchScreen}
        options={{ tabBarLabel: 'Search' }}
      />
      <Tab.Screen
        name="Notifications"
        component={NotificationsScreen}
        options={{ tabBarLabel: 'Alerts' }}
      />
      <Tab.Screen
        name="Profile"
        component={ProfileScreen}
        options={{ tabBarLabel: 'Profile' }}
      />
    </Tab.Navigator>
  )
}
```

## Navigation Hooks

### Typed Navigation Hook

```typescript
// src/hooks/useTypedNavigation.ts
import { useNavigation } from '@react-navigation/native'
import type { NativeStackNavigationProp } from '@react-navigation/native-stack'
import type { RootStackParamList } from '@/navigation/types'

export type AppNavigationProp = NativeStackNavigationProp<RootStackParamList>

export function useTypedNavigation(): AppNavigationProp {
  return useNavigation<AppNavigationProp>()
}

// Usage
function MyComponent() {
  const navigation = useTypedNavigation()

  const goToProfile = () => {
    navigation.navigate('App', {
      screen: 'Profile',
      params: { userId: '123' },
    })
  }

  return <Button onPress={goToProfile}>Go to Profile</Button>
}
```

### Typed Route Hook

```typescript
// src/hooks/useTypedRoute.ts
import { useRoute } from '@react-navigation/native'
import type { RouteProp } from '@react-navigation/native'
import type { RootStackParamList } from '@/navigation/types'

export type AppRouteProp<T extends keyof RootStackParamList> =
  RouteProp<RootStackParamList, T>

export function useTypedRoute<T extends keyof RootStackParamList>(): AppRouteProp<T> {
  return useRoute<AppRouteProp<T>>()
}

// Usage
function ProfileScreen() {
  const route = useTypedRoute<'Profile'>()
  const userId = route.params.userId

  return <Text>User ID: {userId}</Text>
}
```

## Navigation Actions

### Navigating with Parameters

```typescript
import { useTypedNavigation } from '@/hooks/useTypedNavigation'

function HomeScreen() {
  const navigation = useTypedNavigation()

  // Navigate to profile with params
  const navigateToProfile = (userId: string) => {
    navigation.navigate('Profile', { userId })
  }

  // Navigate nested routes
  const navigateToNestedProfile = (userId: string) => {
    navigation.navigate('App', {
      screen: 'Profile',
      params: { userId },
    })
  }

  // Push new screen
  const pushToSettings = () => {
    navigation.push('Settings')
  }

  // Replace current screen
  const replaceWithSettings = () => {
    navigation.replace('Settings')
  }

  // Go back
  const goBack = () => {
    navigation.goBack()
  }

  // Reset to home
  const resetToHome = () => {
    navigation.reset({
      index: 0,
      routes: [{ name: 'Home' }],
    })
  }

  return (
    <View>
      <Button onPress={navigateToProfile}>Go to Profile</Button>
    </View>
  )
}
```

## Deep Linking

### Configuration

```typescript
// src/navigation/index.tsx
import { NavigationContainer } from '@react-navigation/native'
import type { RootStackParamList } from './types'
import { linking } from './linking'
import { RootNavigator } from './RootNavigator'

const navigationRef = React.useRef<NavigationContainerRef>(null)

export function AppNavigator() {
  return (
    <NavigationContainer
      ref={navigationRef}
      linking={linking}
      fallback={<LoadingScreen />}
    >
      <RootNavigator />
    </NavigationContainer>
  )
}

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
          Profile: 'profile/:userId',
          PostDetails: 'post/:postId',
          Settings: {
            path: 'settings',
            screens: {
              AccountSettings: 'account',
              PrivacySettings: 'privacy',
            },
          },
        },
      },
    },
  },
}

export { linking }
```

### Handling Deep Links

```typescript
// src/hooks/useDeepLink.ts
import { useEffect } from 'react'
import { Linking, AppState } from 'react-native'

export function useDeepLink(handleURL: (url: string) => void) {
  useEffect(() => {
    const subscription = Linking.addEventListener('url', ({ url }) => {
      handleURL(url)
    })

    Linking.getInitialURL().then((url) => {
      if (url) {
        handleURL(url)
      }
    })

    return () => {
      subscription.remove()
    }
  }, [handleURL])
}

// Usage
function App() {
  const navigation = useTypedNavigation()

  const handleURL = (url: string) => {
    const parsed = new URL(url)
    const path = parsed.pathname

    if (path.startsWith('/profile/')) {
      const userId = path.split('/')[2]
      navigation.navigate('Profile', { userId })
    }
  }

  useDeepLink(handleURL)

  return <RootNavigator />
}
```

## Advanced Patterns

### Custom Navigation Container

```typescript
// src/navigation/NavigationContainer.tsx
import React, { useState, useCallback } from 'react'
import { NavigationContainer } from '@react-navigation/native'
import type { NavigationState } from '@react-navigation/native'

import { RootNavigator } from './RootNavigator'
import { linking } from './linking'

export function AppNavigationContainer() {
  const [isReady, setIsReady] = useState(false)
  const [initialState, setInitialState] = useState<NavigationState | undefined>()

  useEffect(() => {
    // Restore navigation state
    const restoreState = async () => {
      try {
        const savedState = await AsyncStorage.getItem('navigationState')
        if (savedState) {
          setInitialState(JSON.parse(savedState))
        }
      } catch (err) {
        // Ignore error
      } finally {
        setIsReady(true)
      }
    }

    restoreState()
  }, [])

  const navigationContainerRef = useNavigationContainerRef<RootStackParamList>()

  const onNavigationStateChange = useCallback((state) => {
    // Save navigation state
    AsyncStorage.setItem('navigationState', JSON.stringify(state))
  }, [])

  if (!isReady) {
    return <SplashScreen />
  }

  return (
    <NavigationContainer
      ref={navigationContainerRef}
      initialState={initialState}
      onStateChange={onNavigationStateChange}
      linking={linking}
    >
      <RootNavigator />
    </NavigationContainer>
  )
}
```

### Navigation Service

```typescript
// src/services/navigation.ts
import { NavigationContainerRef } from '@react-navigation/native'
import type { RootStackParamList } from '@/navigation/types'

let navigator: NavigationContainerRef<RootStackParamList> | null = null

export const navigationService = {
  setNavigator: (ref: NavigationContainerRef<RootStackParamList> | null) => {
    navigator = ref
  },

  navigate: (
    name: keyof RootStackParamList,
    params?: object
  ) => {
    navigator?.navigate(name as never, params as never)
  },

  goBack: () => {
    navigator?.goBack()
  },

  reset: (state: Parameters<NavigationContainerRef['reset']>[0]) => {
    navigator?.reset(state)
  },

  getCurrentRoute: () => {
    return navigator?.getCurrentRoute()
  },
}

// Usage from anywhere
import { navigationService } from '@/services/navigation'

function someFunction() {
  navigationService.navigate('Profile', { userId: '123' })
}
```

---

**Remember**: Always use TypeScript for navigation to catch errors at compile time. Keep navigation state minimal and derive what you can from route parameters and app state.
