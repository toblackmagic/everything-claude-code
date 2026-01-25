---
name: rn-component
description: Generate React Native components with best practices and proper typing
---

# /rn-component

Create React Native components with proper structure, TypeScript types, and best practices.

## Usage

```
/rn-component [component-name] [options]
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--type` | Component type: functional, memo | functional |
| `--platform` | Platform: shared, ios, android | shared |
| `--props` | Generate props interface | true |
| `--styles` | Include StyleSheet | true |
| `--dir` | Target directory (src/components) | src/components |
| `--navigation` | Add navigation props | false |

## Examples

```bash
# Basic component
/rn-component Button

# Memoized component
/rn-component UserCard --type memo

# Platform-specific components
/rn-component Header --platform ios
/rn-component Header --platform android

# Component with navigation
/rn-component ProfileScreen --navigation

# Specify directory
/rn-component forms/TextInput --dir src/components
```

## Generated Template

### Functional Component

```typescript
// src/components/Button/Button.tsx
import React, { useCallback } from 'react'
import {
  TouchableOpacity,
  Text,
  StyleSheet,
  GestureResponderEvent,
  StyleProp,
  ViewStyle,
  TextStyle,
} from 'react-native'

export interface ButtonProps {
  title: string
  onPress: (event: GestureResponderEvent) => void
  variant?: 'primary' | 'secondary' | 'outline'
  disabled?: boolean
  style?: StyleProp<ViewStyle>
  textStyle?: StyleProp<TextStyle>
  testID?: string
}

export function Button({
  title,
  onPress,
  variant = 'primary',
  disabled = false,
  style,
  textStyle,
  testID,
}: ButtonProps) {
  const handlePress = useCallback((event: GestureResponderEvent) => {
    if (!disabled) {
      onPress(event)
    }
  }, [disabled, onPress])

  return (
    <TouchableOpacity
      style={[
        styles.button,
        styles[variant],
        disabled && styles.disabled,
        style,
      ]}
      onPress={handlePress}
      disabled={disabled}
      activeOpacity={0.7}
      testID={testID}
    >
      <Text
        style={[
          styles.text,
          styles[`${variant}Text`],
          disabled && styles.disabledText,
          textStyle,
        ]}
      >
        {title}
      </Text>
    </TouchableOpacity>
  )
}

const styles = StyleSheet.create({
  button: {
    paddingVertical: 12,
    paddingHorizontal: 24,
    borderRadius: 8,
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: 48,
  },
  primary: {
    backgroundColor: '#007AFF',
  },
  secondary: {
    backgroundColor: '#5856D6',
  },
  outline: {
    backgroundColor: 'transparent',
    borderWidth: 2,
    borderColor: '#007AFF',
  },
  disabled: {
    opacity: 0.5,
  },
  text: {
    fontSize: 16,
    fontWeight: '600',
    color: '#fff',
  },
  primaryText: {
    color: '#fff',
  },
  secondaryText: {
    color: '#fff',
  },
  outlineText: {
    color: '#007AFF',
  },
  disabledText: {
    color: '#999',
  },
})
```

### Memo Component

```typescript
// src/components/UserCard/UserCard.tsx
import React, { memo } from 'react'
import { View, Text, Image, StyleSheet, ViewStyle } from 'react-native'

export interface UserCardProps {
  userId: string
  name: string
  avatar?: string
  email: string
  style?: ViewStyle
  onPress?: () => void
}

export const UserCard = memo(function UserCard({
  userId,
  name,
  avatar,
  email,
  style,
  onPress,
}: UserCardProps) {
  return (
    <TouchableOpacity
      style={[styles.container, style]}
      onPress={onPress}
      activeOpacity={0.7}
    >
      <Image
        source={{ uri: avatar || 'https://example.com/default-avatar.png' }}
        style={styles.avatar}
      />
      <View style={styles.info}>
        <Text style={styles.name}>{name}</Text>
        <Text style={styles.email}>{email}</Text>
      </View>
    </TouchableOpacity>
  })
})

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 16,
    backgroundColor: '#fff',
    borderRadius: 8,
    ...Platform.select({
      ios: {
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.1,
        shadowRadius: 4,
      },
      android: {
        elevation: 4,
      },
    }),
  },
  avatar: {
    width: 50,
    height: 50,
    borderRadius: 25,
    marginRight: 12,
  },
  info: {
    flex: 1,
  },
  name: {
    fontSize: 16,
    fontWeight: '600',
    color: '#000',
  },
  email: {
    fontSize: 14,
    color: '#666',
    marginTop: 2,
  },
})
```

### Platform-Specific Component

```typescript
// src/components/Header/Header.tsx (shared)
export { default as Header } from './Header.ios'
// or
export { default as Header } from './Header.android'

// src/components/Header/Header.ios.tsx
import React from 'react'
import { View, Text, StyleSheet, SafeAreaView } from 'react-native'

export interface HeaderProps {
  title: string
}

export default function Header({ title }: HeaderProps) {
  return (
    <SafeAreaView style={styles.safeArea}>
      <View style={styles.container}>
        <Text style={styles.title}>{title}</Text>
      </View>
    </SafeAreaView>
  )
}

const styles = StyleSheet.create({
  safeArea: {
    backgroundColor: '#007AFF',
  },
  container: {
    height: 44,
    alignItems: 'center',
    justifyContent: 'center',
  },
  title: {
    fontSize: 17,
    fontWeight: '600',
    color: '#fff',
  },
})

// src/components/Header/Header.android.tsx
import React from 'react'
import { View, Text, StyleSheet } from 'react-native'

export interface HeaderProps {
  title: string
}

export default function Header({ title }: HeaderProps) {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>{title}</Text>
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    height: 56,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#007AFF',
    elevation: 4,
  },
  title: {
    fontSize: 20,
    fontWeight: '500',
    color: '#fff',
  },
})
```

## Best Practices Applied

1. **TypeScript**: Full type safety with prop interfaces
2. **Memoization**: useCallback for event handlers, memo for components
3. **Accessibility**: testID props for testing
4. **Platform Support**: Platform-specific styles and code
5. **Performance**: Proper prop destructuring and style optimization
6. **Naming**: Clear, descriptive component and prop names

## File Organization

```
src/components/
├── Button/
│   ├── Button.tsx
│   ├── Button.test.tsx
│   └── index.ts
├── UserCard/
│   ├── UserCard.tsx
│   ├── UserCard.test.tsx
│   └── index.ts
└── index.ts
```

## Component Guidelines

### When to use memo

- Components that re-render often with same props
- List items in FlatList
- Components receiving objects/arrays as props

### When to add navigation

- Screen components
- Components that navigate on press
- Deep linking handlers

### Platform-specific considerations

- Use `.ios.tsx` / `.android.tsx` for significant platform differences
- Use `Platform.select()` for style differences
- Test on both platforms when using platform code

---

**Tip**: Always extract reusable styles into a StyleSheet instead of inline style objects for better performance.
