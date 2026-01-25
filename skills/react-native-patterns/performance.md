# React Native Performance Optimization

Performance optimization strategies and patterns for React Native applications.

## Rendering Optimization

### Component Memoization

```typescript
import React, { memo, useCallback, useMemo } from 'react'
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native'

// ✅ Memoize expensive components
const ExpensiveComponent = memo(({ data, onPress }: {
  data: Item[]
  onPress: (item: Item) => void
}) => {
  // Memoize expensive calculations
  const sortedData = useMemo(() => {
    return data.sort((a, b) => b.value - a.value)
  }, [data])

  // Memoize callbacks
  const handlePress = useCallback((item: Item) => {
    onPress(item)
  }, [onPress])

  return (
    <View>
      {sortedData.map(item => (
        <TouchableOpacity key={item.id} onPress={() => handlePress(item)}>
          <Text>{item.name}</Text>
        </TouchableOpacity>
      ))}
    </View>
  )
})

// Use custom comparison for complex props
const CustomMemoComponent = memo(({ user, settings }: Props) => {
  return <UserProfile user={user} settings={settings} />
}, (prevProps, nextProps) => {
  return (
    prevProps.user.id === nextProps.user.id &&
    prevProps.settings.theme === nextProps.settings.theme
  )
})
```

### Avoid Inline Functions

```typescript
// ❌ BAD: Creates new function on every render
function BadList({ items }) {
  return (
    <FlatList
      data={items}
      renderItem={({ item }) => (
        <ItemComponent
          item={item}
          onPress={() => handlePress(item)}  // New function every render
        />
      )}
    />
  )
}

// ✅ GOOD: Use useCallback
function GoodList({ items }) {
  const handlePress = useCallback((item: Item) => {
    // Handle press
  }, [])

  const renderItem: ListRenderItem<Item> = useCallback(({ item }) => (
    <ItemComponent item={item} onPress={handlePress} />
  ), [handlePress])

  return <FlatList data={items} renderItem={renderItem} />
}
```

## List Optimization

### FlatList Performance

```typescript
import { FlatList, View } from 'react-native'

interface OptimizedListProps {
  data: Item[]
  onPress: (item: Item) => void
}

function OptimizedList({ data, onPress }: OptimizedListProps) {
  // Always provide keyExtractor
  const keyExtractor = useCallback((item: Item) => item.id, [])

  // Memoize render item
  const renderItem: ListRenderItem<Item> = useCallback(({ item }) => (
    <ListItem item={item} onPress={onPress} />
  ), [onPress])

  // Memoize separators
  const ItemSeparator = useCallback(() => (
    <View style={{ height: 1, backgroundColor: '#eee' }} />
  ), [])

  // Memoize header
  const ListHeader = useCallback(() => (
    <View style={{ padding: 16 }}>
      <Text>Total: {data.length}</Text>
    </View>
  ), [data.length])

  return (
    <FlatList
      data={data}
      keyExtractor={keyExtractor}
      renderItem={renderItem}
      ItemSeparatorComponent={ItemSeparator}
      ListHeaderComponent={ListHeader}

      // Performance props
      removeClippedSubviews={true}     // Remove off-screen views
      maxToRenderPerBatch={10}          // Items per batch
      updateCellsBatchingPeriod={50}    // Batch update delay (ms)
      initialNumToRender={10}           // Initial items
      windowSize={5}                    // Render window size
      legacyImplementation={false}      // Use new implementation

      // Memory management
      onEndReachedThreshold={0.5}       // Trigger 50% from end
      onEndReached={loadMore}           // Load more callback
    />
  )
}

// Memoize list item
const ListItem = memo(({ item, onPress }: { item: Item; onPress: (item: Item) => void }) => (
  <TouchableOpacity onPress={() => onPress(item)}>
    <Text>{item.title}</Text>
  </TouchableOpacity>
))
```

### VirtualizedList with Variable Sizes

```typescript
import { VirtualizedList, View } from 'react-native'

interface VariableSizeListProps {
  data: Item[]
  getItemSize: (item: Item) => number
}

function VariableSizeList({ data, getItemSize }: VariableSizeListProps) {
  const getItemLayout = useCallback((data: any, index: number) => {
    const item = data[index]
    const length = getItemSize(item)
    const offset = data.slice(0, index).reduce((sum: number, i: Item) => sum + getItemSize(i), 0)
    return { length, offset, index }
  }, [getItemSize])

  return (
    <VirtualizedList
      data={data}
      getItemCount={() => data.length}
      getItem={(data, index) => data[index]}
      keyExtractor={(item) => item.id}
      renderItem={({ item }) => <VariableItem item={item} />}
      getItemLayout={getItemLayout}
    />
  )
}
```

## Image Optimization

### Image Caching and Optimization

```typescript
import { Image, ImageStyle } from 'react-native'
import FastImage from 'react-native-fast-image'

// ✅ Use FastImage for cached images
function OptimizedImage({ uri, style }: { uri: string; style: ImageStyle }) {
  return (
    <FastImage
      source={{ uri, priority: FastImage.priority.high }}
      style={style}
      resizeMode={FastImage.resizeMode.cover}
    />
  )
}

// Progressive image loading
function ProgressiveImage({ thumbnailUri, imageUri, style }: ProgressiveImageProps) {
  const [loaded, setLoaded] = useState(false)

  return (
    <View style={style}>
      <FastImage
        source={{ uri: thumbnailUri }}
        style={StyleSheet.absoluteFill}
      />
      <FastImage
        source={{ uri: imageUri }}
        style={StyleSheet.absoluteFill}
        onLoad={() => setLoaded(true)}
      />
    </View>
  )
}

// Image preloading
function preloadImages(urls: string[]) {
  const images = urls.map(uri => ({ uri }))
  FastImage.preload(images)
}

// Usage in app startup
useEffect(() => {
  preloadImages([
    'https://example.com/image1.jpg',
    'https://example.com/image2.jpg',
  ])
}, [])
```

### Image Resizing

```typescript
import { Image } from 'react-native'
import ImageResizer from 'react-native-image-resizer'

async function resizeImageForUpload(uri: string) {
  const resizedImage = await ImageResizer.createResizedImage(
    uri,
    1024,  // maxWidth
    1024,  // maxHeight
    'JPEG',
    80,    // quality
    0,     // rotation
    null   // outputPath
  )
  return resizedImage.uri
}

// Get optimal image size for display
function getOptimalImageSize(
  imageWidth: number,
  imageHeight: number,
  containerWidth: number
) {
  const aspectRatio = imageWidth / imageHeight
  return {
    width: containerWidth,
    height: containerWidth / aspectRatio,
  }
}
```

## State Management Optimization

### Avoid Unnecessary Re-renders

```typescript
import { useState, useCallback, useRef } from 'react'
import { View, Text, TextInput } from 'react-native'

// ❌ BAD: State updates cause full re-render
function BadForm() {
  const [form, setForm] = useState({
    username: '',
    email: '',
    password: '',
  })

  return (
    <View>
      <TextInput
        value={form.username}
        onChangeText={(text) => setForm({ ...form, username: text })}
      />
      {/* More inputs... */}
    </View>
  )
}

// ✅ GOOD: Split state or use refs
function GoodForm() {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  return (
    <View>
      <TextInput value={username} onChangeText={setUsername} />
      <TextInput value={email} onChangeText={setEmail} />
      <TextInput value={password} onChangeText={setPassword} />
    </View>
  )
}

// For very large forms, use refs
function LargeForm() {
  const usernameRef = useRef<string>('')
  const emailRef = useRef<string>('')

  const handleSubmit = () => {
    const formData = {
      username: usernameRef.current,
      email: emailRef.current,
    }
    submitForm(formData)
  }

  return (
    <View>
      <TextInput onChangeText={(text) => { usernameRef.current = text }} />
      <Button onPress={handleSubmit}>Submit</Button>
    </View>
  )
}
```

### Context Optimization

```typescript
import { createContext, useContext, useMemo, useCallback } from 'react'

// ❌ BAD: Everything re-renders when context changes
const BadContext = createContext<{
  user: User | null
  settings: Settings
  actions: {
    setUser: (user: User) => void
    updateSettings: (settings: Partial<Settings>) => void
  }
}>(null!)

function BadProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [settings, setSettings] = useState<Settings>(defaultSettings)

  const value = {
    user,
    settings,
    actions: {
      setUser,
      updateSettings: (newSettings) => setSettings({ ...settings, ...newSettings }),
    },
  }

  return <BadContext.Provider value={value}>{children}</BadContext.Provider>
}

// ✅ GOOD: Split contexts
const UserContext = createContext<User | null>(null)
const SettingsContext = createContext<Settings>(defaultSettings)
const UserActionsContext = createContext<{
  setUser: (user: User) => void
}>(null!)

function GoodProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [settings, setSettings] = useState<Settings>(defaultSettings)

  const userActions = useMemo(() => ({
    setUser,
  }), [])

  return (
    <UserContext.Provider value={user}>
      <UserActionsContext.Provider value={userActions}>
        <SettingsContext.Provider value={settings}>
          {children}
        </SettingsContext.Provider>
      </UserActionsContext.Provider>
    </UserContext.Provider>
  )
}

// Components only re-render when their specific context changes
function UserProfile() {
  const user = useContext(UserContext)  // Only re-renders when user changes
  return <Text>{user?.name}</Text>
}
```

## Animation Performance

### Use Native Driver

```typescript
import { Animated } from 'react-native'

// ✅ Always use native driver when possible
function NativeAnimation() {
  const fadeAnim = useRef(new Animated.Value(0)).current

  useEffect(() => {
    Animated.timing(fadeAnim, {
      toValue: 1,
      duration: 300,
      useNativeDriver: true,  // Runs on UI thread
    }).start()
  }, [])

  return (
    <Animated.View style={{ opacity: fadeAnim }}>
      <Content />
    </Animated.View>
  )
}

// Native driver supported properties:
// - transform (translate, scale, rotate)
// - opacity
// - rotation (as part of transform)

// ❌ NOT supported (requires JS bridge):
// - width, height
// - backgroundColor
// - color
// - margin, padding
// - borderWidth
```

### Layout Animation

```typescript
import { LayoutAnimation, Platform, UIManager } from 'react-native'

// Enable layout animations on Android
if (Platform.OS === 'android' && UIManager.setLayoutAnimationEnabledExperimental) {
  UIManager.setLayoutAnimationEnabledExperimental(true)
}

function LayoutAnimationExample() {
  const [expanded, setExpanded] = useState(false)

  const toggle = () => {
    LayoutAnimation.configureNext({
      duration: 300,
      create: { type: 'easeInEaseOut', property: 'opacity' },
      update: { type: 'spring', springDamping: 0.7 },
      delete: { type: 'easeInEaseOut', property: 'opacity' },
    })
    setExpanded(!expanded)
  }

  return (
    <View>
      <Button onPress={toggle}>Toggle</Button>
      {expanded && <ExpandedContent />}
    </View>
  )
}
```

## Memory Management

### Cleanup Effects

```typescript
import { useEffect, useRef } from 'react'

function DataFetcher() {
  const abortControllerRef = useRef<AbortController | null>(null)

  useEffect(() => {
    abortControllerRef.current = new AbortController()

    const fetchData = async () => {
      try {
        const response = await fetch('/api/data', {
          signal: abortControllerRef.current.signal,
        })
        const data = await response.json()
        // Handle data
      } catch (error) {
        if (error.name !== 'AbortError') {
          // Handle error
        }
      }
    }

    fetchData()

    return () => {
      abortControllerRef.current?.abort()
    }
  }, [])

  return <Content />
}

// Cleanup event listeners
function LocationTracker() {
  useEffect(() => {
    const subscription = Geolocation.watchPosition(
      (position) => {
        // Handle position
      },
      (error) => {
        // Handle error
      }
    )

    return () => {
      Geolocation.clearWatch(subscription)
    }
  }, [])

  return <MapComponent />
}
```

### Image Memory Management

```typescript
import { Image } from 'react-native'

function ImageGallery({ images }: { images: string[] }) {
  const [currentIndex, setCurrentIndex] = useState(0)

  useEffect(() => {
    // Preload next image
    if (currentIndex < images.length - 1) {
      Image.prefetch(images[currentIndex + 1])
    }

    // Unload distant images
    for (let i = 0; i < images.length; i++) {
      if (Math.abs(i - currentIndex) > 2) {
        // Consider implementing image cache cleanup
      }
    }
  }, [currentIndex, images])

  return (
    <ScrollView horizontal>
      {images.map((uri, index) => (
        <Image
          key={uri}
          source={{ uri }}
          style={{ width: 300, height: 300 }}
          resizeMode="contain"
        />
      ))}
    </ScrollView>
  )
}
```

## Bundle Optimization

### Code Splitting

```typescript
// Use React.lazy for large components
import React, { lazy, Suspense } from 'react'

const HeavyChart = lazy(() => import('./HeavyChart'))
const SettingsScreen = lazy(() => import('./SettingsScreen'))

function App() {
  return (
    <Suspense fallback={<LoadingScreen />}>
      <Routes>
        <Route path="/" element={<HomeScreen />} />
        <Route path="/chart" element={<HeavyChart />} />
        <Route path="/settings" element={<SettingsScreen />} />
      </Routes>
    </Suspense>
  )
}
```

### Proguard Configuration (Android)

```proguard
# android/app/proguard-rules.pro

# Keep React Native classes
-keep class com.facebook.react.** { *; }

# Keep your app classes
-keep class com.yourapp.** { *; }

# Remove logging
-assumenosideeffects class android.util.Log {
  public static *** d(...);
  public static *** v(...);
}
```

## Performance Monitoring

### Systrace for Performance Profiling

```typescript
import { Performance } from 'react-native'

function markPerformance(name: string) {
  if (__DEV__) {
    Performance.mark(name)
  }
}

function measurePerformance(name: string, startMark: string) {
  if (__DEV__) {
    Performance.measure(name, startMark)
    const measure = Performance.getEntriesByName(name)[0]
    console.log(`${name}: ${measure.duration}ms`)
  }
}

// Usage
async function loadData() {
  markPerformance('loadData-start')
  // Load data...
  const data = await fetch('/api/data').then(r => r.json())
  measurePerformance('loadData', 'loadData-start')
  return data
}
```

### Performance Overlay

```typescript
import { DevSettings } from 'react-native'

// Enable performance overlay in dev
if (__DEV__) {
  DevSettings.setIsDebuggingRemotely(true)
}

// Or use react-native-performance library
import { PerformanceStatsView } from 'react-native-performance'

function App() {
  return (
    <>
      <YourApp />
      {__DEV__ && <PerformanceStatsView />}
    </>
  )
}
```

---

**Remember**: Always profile before optimizing. Use React DevTools, Systrace, and the Performance Monitor to identify actual bottlenecks. Premature optimization can lead to complex code with minimal benefits.
