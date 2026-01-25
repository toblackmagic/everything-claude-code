# React Native Component Patterns

Component patterns and best practices for React Native applications.

## Platform-Specific Components

### Platform Module Pattern

```typescript
import { Platform, View, Text, StyleSheet } from 'react-native'

interface PlatformAwareProps {
  children: React.ReactNode
}

export function PlatformAwareContainer({ children }: PlatformAwareProps) {
  return (
    <View style={styles.container}>
      {Platform.OS === 'ios' && <IOSHeader />}
      {Platform.OS === 'android' && <AndroidHeader />}
      {children}
    </View>
  )
}

// Platform-specific styles
const styles = StyleSheet.create({
  container: {
    flex: 1,
    ...Platform.select({
      ios: {
        backgroundColor: '#f5f5f5',
      },
      android: {
        backgroundColor: '#ffffff',
      },
    }),
  },
})
```

### Platform File Extension Pattern

```
components/
├── Button.tsx          # Shared code
├── Button.ios.tsx      # iOS specific
└── Button.android.tsx  # Android specific
```

```typescript
// Button.tsx
export { default } from './Button.ios'
// Metro bundler will automatically pick the correct file
```

## List Components

### FlatList with Optimizations

```typescript
import React, { useCallback, useMemo } from 'react'
import {
  FlatList,
  ListRenderItem,
  StyleSheet,
  Text,
  View,
} from 'react-native'

interface Item {
  id: string
  title: string
  description: string
}

interface OptimizedListProps {
  data: Item[]
  onPressItem: (item: Item) => void
}

export function OptimizedList({ data, onPressItem }: OptimizedListProps) {
  // Memoize key extractor
  const keyExtractor = useCallback((item: Item) => item.id, [])

  // Memoize render item
  const renderItem: ListRenderItem<Item> = useCallback(({ item }) => (
    <ListItem
      item={item}
      onPress={() => onPressItem(item)}
    />
  ), [onPressItem])

  // Memoize ListHeaderComponent
  const ListHeader = useCallback(() => (
    <View style={styles.header}>
      <Text style={styles.headerText}>{data.length} Items</Text>
    </View>
  ), [data.length])

  return (
    <FlatList
      data={data}
      keyExtractor={keyExtractor}
      renderItem={renderItem}
      ListHeaderComponent={ListHeader}
      ItemSeparatorComponent={ItemSeparator}
      removeClippedSubviews={true}  // Memory optimization
      maxToRenderPerBatch={10}       // Reduce initial render
      windowSize={5}                 // Render window size
      initialNumToRender={10}        // Initial items
      contentContainerStyle={styles.listContent}
    />
  )
}

// Memoized list item
const ListItem = React.memo(({ item, onPress }: { item: Item; onPress: () => void }) => (
  <TouchableOpacity onPress={onPress} style={styles.item}>
    <Text style={styles.title}>{item.title}</Text>
    <Text style={styles.description}>{item.description}</Text>
  </TouchableOpacity>
))

const ItemSeparator = () => <View style={styles.separator} />

const styles = StyleSheet.create({
  listContent: {
    paddingVertical: 8,
  },
  header: {
    padding: 16,
    backgroundColor: '#f5f5f5',
  },
  headerText: {
    fontSize: 14,
    fontWeight: '600',
  },
  item: {
    padding: 16,
    backgroundColor: '#fff',
  },
  title: {
    fontSize: 16,
    fontWeight: '500',
  },
  description: {
    fontSize: 14,
    color: '#666',
    marginTop: 4,
  },
  separator: {
    height: 1,
    backgroundColor: '#e0e0e0',
    marginLeft: 16,
  },
})
```

### SectionList Pattern

```typescript
import { SectionList } from 'react-native'

interface Section {
  title: string
  data: Item[]
}

interface SectionedListProps {
  sections: Section[]
}

export function SectionedList({ sections }: SectionedListProps) {
  return (
    <SectionList
      sections={sections}
      keyExtractor={(item) => item.id}
      renderItem={({ item }) => <ListItem item={item} />}
      renderSectionHeader={({ section: { title } }) => (
        <SectionHeader title={title} />
      )}
      ItemSeparatorComponent={ItemSeparator}
      SectionSeparatorComponent={SectionSeparator}
      stickySectionHeadersEnabled={true}
    />
  )
}
```

## Custom Hooks

### useAppState Hook

```typescript
import { useEffect, useState } from 'react'
import { AppState, AppStateStatus } from 'react-native'

export function useAppState(initialState: AppStateStatus = AppState.currentState) {
  const [appState, setAppState] = useState<AppStateStatus>(initialState)

  useEffect(() => {
    const subscription = AppState.addEventListener('change', (nextAppState) => {
      setAppState(nextAppState)
    })

    return () => {
      subscription.remove()
    }
  }, [])

  return appState
}

// Usage
function AppStateWatcher() {
  const appState = useAppState()

  return (
    <Text>Current state: {appState}</Text>
  )
}
```

### useDimensions Hook

```typescript
import { useEffect, useState } from 'react'
import { Dimensions, ScaledSize } from 'react-native'

export function useDimensions() {
  const [dimensions, setDimensions] = useState(() => Dimensions.get('window'))

  useEffect(() => {
    const subscription = Dimensions.addEventListener('change', ({ window }) => {
      setDimensions(window)
    })

    return () => subscription?.remove()
  }, [])

  return dimensions
}

// Usage
function ResponsiveComponent() {
  const { width, height } = useDimensions()
  const isPortrait = height > width

  return (
    <View style={{ width, height }}>
      {isPortrait ? <PortraitLayout /> : <LandscapeLayout />}
    </View>
  )
}
```

### useKeyboard Hook

```typescript
import { useEffect, useState } from 'react'
import { Keyboard, KeyboardMetrics } from 'react-native'

export function useKeyboard() {
  const [keyboard, setKeyboard] = useState<KeyboardMetrics>({
    endCoordinates: { height: 0, screenX: 0, screenY: 0, width: 0 },
  })
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    const showSubscription = Keyboard.addListener('keyboardDidShow', (e) => {
      setKeyboard(e.endCoordinates)
      setVisible(true)
    })

    const hideSubscription = Keyboard.addListener('keyboardDidHide', () => {
      setVisible(false)
    })

    return () => {
      showSubscription.remove()
      hideSubscription.remove()
    }
  }, [])

  return { keyboard, visible }
}

// Usage
function KeyboardAwareForm() {
  const { keyboard, visible } = useKeyboard()

  return (
    <View style={{ paddingBottom: visible ? keyboard.height : 0 }}>
      <TextInput placeholder="Username" />
      <TextInput placeholder="Password" />
    </View>
  )
}
```

## Compound Components

### Tab Bar Compound Component

```typescript
import React, { createContext, useContext, useState } from 'react'
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native'

interface TabBarContextValue {
  activeTab: string
  setActiveTab: (tab: string) => void
}

const TabBarContext = createContext<TabBarContextValue | undefined>(undefined)

function useTabBarContext() {
  const context = useContext(TabBarContext)
  if (!context) {
    throw new Error('TabBar components must be used within TabBar')
  }
  return context
}

interface TabBarProps {
  children: React.ReactNode
  defaultTab: string
}

export function TabBar({ children, defaultTab }: TabBarProps) {
  const [activeTab, setActiveTab] = useState(defaultTab)

  return (
    <TabBarContext.Provider value={{ activeTab, setActiveTab }}>
      {children}
    </TabBarContext.Provider>
  )
}

export function TabBarList({ children }: { children: React.ReactNode }) {
  return <View style={styles.tabList}>{children}</View>
}

interface TabProps {
  id: string
  children: React.ReactNode
}

export function Tab({ id, children }: TabProps) {
  const { activeTab, setActiveTab } = useTabBarContext()
  const isActive = activeTab === id

  return (
    <TouchableOpacity
      style={[styles.tab, isActive && styles.activeTab]}
      onPress={() => setActiveTab(id)}
      activeOpacity={0.7}
    >
      <Text style={[styles.tabText, isActive && styles.activeTabText]}>
        {children}
      </Text>
    </TouchableOpacity>
  )
}

export function TabBarContent({ children, id }: { children: React.ReactNode; id: string }) {
  const { activeTab } = useTabBarContext()

  if (activeTab !== id) return null

  return <View style={styles.content}>{children}</View>
}

// Usage
function Example() {
  return (
    <TabBar defaultTab="home">
      <TabBarList>
        <Tab id="home">Home</Tab>
        <Tab id="search">Search</Tab>
        <Tab id="profile">Profile</Tab>
      </TabBarList>
      <TabBarContent id="home">
        <HomeScreen />
      </TabBarContent>
      <TabBarContent id="search">
        <SearchScreen />
      </TabBarContent>
      <TabBarContent id="profile">
        <ProfileScreen />
      </TabBarContent>
    </TabBar>
  )
}

const styles = StyleSheet.create({
  tabList: {
    flexDirection: 'row',
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  tab: {
    flex: 1,
    paddingVertical: 12,
    alignItems: 'center',
  },
  activeTab: {
    borderBottomWidth: 2,
    borderBottomColor: '#007AFF',
  },
  tabText: {
    fontSize: 14,
    color: '#666',
  },
  activeTabText: {
    color: '#007AFF',
    fontWeight: '600',
  },
  content: {
    flex: 1,
  },
})
```

## Render Props Pattern

### DataSource Component

```typescript
import React, { useState, useEffect } from 'react'
import { View, Text, ActivityIndicator, FlatList } from 'react-native'

interface DataSourceProps<T> {
  fetchData: () => Promise<T[]>
  children: (props: {
    data: T[] | null
    loading: boolean
    error: Error | null
    refetch: () => void
  }) => React.ReactNode
}

export function DataSource<T>({ fetchData, children }: DataSourceProps<T>) {
  const [data, setData] = useState<T[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const fetch = async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await fetchData()
      setData(result)
    } catch (err) {
      setError(err as Error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetch()
  }, [fetchData])

  return <>{children({ data, loading, error, refetch: fetch })}</>
}

// Usage
function UserList() {
  return (
    <DataSource
      fetchData={() => fetch('/api/users').then(r => r.json())}
    >
      {({ data, loading, error, refetch }) => {
        if (loading) return <ActivityIndicator />
        if (error) return <Text>Error: {error.message}</Text>
        return (
          <FlatList
            data={data}
            keyExtractor={(item) => item.id}
            renderItem={({ item }) => <Text>{item.name}</Text>}
            refreshing={loading}
            onRefresh={refetch}
          />
        )
      }}
    </DataSource>
  )
}
```

## Component Composition

### Card Compound Component

```typescript
import { View, Text, StyleSheet, ViewStyle } from 'react-native'

interface CardProps {
  children: React.ReactNode
  variant?: 'default' | 'outlined' | 'elevated'
  style?: ViewStyle
}

export function Card({ children, variant = 'default', style }: CardProps) {
  return (
    <View style={[styles.card, styles[variant], style]}>
      {children}
    </View>
  )
}

export function CardHeader({ children }: { children: React.ReactNode }) {
  return <View style={styles.header}>{children}</View>
}

export function CardBody({ children }: { children: React.ReactNode }) {
  return <View style={styles.body}>{children}</View>
}

export function CardFooter({ children }: { children: React.ReactNode }) {
  return <View style={styles.footer}>{children}</View>
}

// Usage
function Example() {
  return (
    <Card variant="elevated">
      <CardHeader>
        <Text style={styles.title}>Card Title</Text>
      </CardHeader>
      <CardBody>
        <Text>Card content goes here</Text>
      </CardBody>
      <CardFooter>
        <Button>Learn More</Button>
      </CardFooter>
    </Card>
  )
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: '#fff',
    borderRadius: 8,
    overflow: 'hidden',
  },
  default: {
    borderWidth: 1,
    borderColor: '#e0e0e0',
  },
  outlined: {
    borderWidth: 2,
    borderColor: '#007AFF',
  },
  elevated: {
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
  header: {
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#f0f0f0',
  },
  body: {
    padding: 16,
  },
  footer: {
    padding: 16,
    borderTopWidth: 1,
    borderTopColor: '#f0f0f0',
  },
  title: {
    fontSize: 18,
    fontWeight: '600',
  },
})
```

---

**Remember**: Always memoize components, use proper key extraction, and implement platform-specific optimizations for the best mobile experience.
