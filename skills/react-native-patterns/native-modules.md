# React Native Native Modules

Guide to creating and using native modules in React Native for iOS and Android.

## When to Use Native Modules

### Use Native Modules For:
- Accessing platform-specific APIs not available in JavaScript
- Implementing performance-critical code
- Integrating third-party native SDKs
- Hardware access (Bluetooth, NFC, biometrics)
- System-level features (background tasks, permissions)

### Alternatives to Consider First:
1. **Expo Modules** - Check if Expo already provides a module
2. **React Native Community** - Search for existing community modules
3. **React Native API** - Check if React Native has built-in support

## Expo Config Plugins (Recommended for Expo)

### Creating a Config Plugin

```typescript
// plugins/withMyPlugin.ts
import { ConfigPlugin, withAppBuildGradle, withInfoPlist, withProject } from '@expo/config-plugins'

const withMyAndroidPermission: ConfigPlugin<{ permissionName: string }> = (config, { permissionName }) => {
  return withAppBuildGradle(config, (config) => {
    config.modResults.contents += `\n${permissionName}\n`
    return config
  })
}

const withMyiOSPermission: ConfigPlugin<{ permissionName: string }> = (config, { permissionName }) => {
  return withInfoPlist(config, (config) => {
    config.modResults.NSCameraUsageDescription = permissionName
    return config
  })
}

export const withMyPlugin: ConfigPlugin<{ androidPermission?: string; iosPermission?: string }> = (
  config,
  { androidPermission, iosPermission }
) => {
  if (androidPermission) {
    config = withMyAndroidPermission(config, { permissionName: androidPermission })
  }
  if (iosPermission) {
    config = withMyiOSPermission(config, { permissionName: iosPermission })
  }
  return config
}

// app.config.js
export default {
  name: 'MyApp',
  plugins: [
    ['../plugins/withMyPlugin', {
      androidPermission: 'android.permission.CAMERA',
      iosPermission: 'Allow camera access'
    }]
  ]
}
```

## React Native CLI Native Modules

### Module Structure

```
NativeModule/
├── ios/
│   └── NativeModule.podspec
├── android/
│   └── build.gradle
├── src/
│   └── index.tsx
├── NativeModule.podspec
└── package.json
```

### TypeScript Bridge Definition

```typescript
// src/index.tsx
import { NativeModules, NativeEventEmitter, Platform } from 'react-native'

type NativeModuleType = {
  multiply(a: number, b: number): Promise<number>
  addListener(eventType: string): void
  removeListeners(count: number): void
}

const LINKING_ERROR =
  `The package 'com.nativemodule' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n'

const NativeModule: NativeModuleType = NativeModules.NativeModule
  ? NativeModules.NativeModule
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR)
        },
      }
    )

export default NativeModule

// Event emitter for native events
export const NativeModuleEventEmitter = new NativeEventEmitter(
  NativeModules.NativeModule
)
```

### iOS Native Module (Swift)

```swift
// ios/NativeModule.swift
import React
import Foundation

@objc(NativeModule)
class NativeModule: NSObject {
  @objc
  static func requiresMainQueueSetup() -> Bool {
    return false
  }

  @objc(multiply:withResolver:withRejecter:)
  func multiply(_ a: Float, b: Float, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    let result = a * b
    resolve(result)
  }

  // Emit event to JavaScript
  func sendEvent(_ eventName: String, body: Any?) {
    self.sendEvent(withName: eventName, body: body)
  }
}
```

```swift
// ios/NativeModuleBridge.m
#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(NativeModule, NSObject)

RCT_EXTERN_METHOD(multiply:(float)a
                  withB:(float)b
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

@end
```

```ruby
# ios/NativeModule.podspec
Pod::Spec.new do |s|
  s.name           = 'NativeModule'
  s.version        = '1.0.0'
  s.summary        = 'A native module for React Native'
  s.description    = <<-DESC
    A native module that provides multiply functionality
  DESC
  s.homepage       = 'https://github.com/example/nativemodule'
  s.license        = { :type => 'MIT' }
  s.author         = { 'Your Name' => 'you@example.com' }
  s.platforms      = { :ios => '13.0' }
  s.source         = { :git => 'https://github.com/example/nativemodule.git', :tag => s.version.to_s }
  s.source_files   = 'ios/**/*.{h,m,mm,swift}'
  s.dependency 'React-Core'
end
```

### Android Native Module (Kotlin)

```kotlin
// android/src/main/java/com/nativemodule/NativeModule.kt
package com.nativemodule

import com.facebook.react.bridge.*
import com.facebook.react.modules.core.DeviceEventManagerModule

class NativeModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String {
    return "NativeModule"
  }

  @ReactMethod
  fun multiply(a: Double, b: Double, promise: Promise) {
    val result = a * b
    promise.resolve(result)
  }

  // Send event to JavaScript
  fun sendEvent(eventName: String, payload: WritableMap) {
    reactApplicationContext
      .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
      .emit(eventName, payload)
  }
}
```

```kotlin
// android/src/main/java/com/nativemodule/NativeModulePackage.kt
package com.nativemodule

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

class NativeModulePackage : ReactPackage {
  override fun createNativeModules(
    reactContext: ReactApplicationContext
  ): MutableList<NativeModule> {
    return mutableListOf(NativeModule(reactContext))
  }

  override fun createViewManagers(
    reactContext: ReactApplicationContext
  ): MutableList<ViewManager<*, *>> {
    return mutableListOf()
  }
}
```

```groovy
// android/build.gradle
buildscript {
  ext {
    kotlinVersion = '1.8.0'
  }
}

dependencies {
  implementation "com.facebook.react:react-native:+"
  implementation "org.jetbrains.kotlin:kotlin-stdlib:$kotlinVersion"
}
```

## Native Events

### Sending Events from Native to JS

**iOS (Swift)**:
```swift
func notifyJavaScript() {
  self.sendEvent(withName: "onCustomEvent", body: ["value": 42])
}
```

**Android (Kotlin)**:
```kotlin
fun notifyJavaScript() {
  val params = Arguments.createMap().apply {
    putDouble("value", 42.0)
  }
  sendEvent("onCustomEvent", params)
}
```

**JavaScript Listener**:
```typescript
import { NativeModuleEventEmitter } from './index'

useEffect(() => {
  const subscription = NativeModuleEventEmitter.addListener(
    'onCustomEvent',
    (event) => {
      console.log('Received event:', event)
    }
  )

  return () => {
    subscription.remove()
  }
}, [])
```

## Common Native Module Patterns

### Permission Handling

```typescript
// src/permissions.ts
import { Platform, NativeModules, PermissionsAndroid } from 'react-native'

async function requestPermission(permission: string): Promise<boolean> {
  if (Platform.OS === 'android') {
    const granted = await PermissionsAndroid.request(permission)
    return granted === PermissionsAndroid.RESULTS.GRANTED
  } else {
    // iOS permissions are handled via Info.plist
    return true
  }
}
```

### Background Tasks

```typescript
// src/background.ts
import { AppRegistry } from 'react-native'

const headlessTask = async (taskData) => {
  // Perform background work
  return Promise.resolve()
}

AppRegistry.registerHeadlessTask('BackgroundTask', () => headlessTask)
```

### Native View Manager

```typescript
// src/NativeView.tsx
import { requireNativeComponent, UIManager } from 'react-native'

interface NativeViewProps {
  text: string
  onTextChange?: (text: string) => void
}

const NativeView = requireNativeComponent<NativeViewProps>('NativeView')

export function CustomNativeView({ text, onTextChange }: NativeViewProps) {
  return (
    <NativeView
      style={{ width: 200, height: 100 }}
      text={text}
      onTextChange={(event) => onTextChange?.(event.nativeEvent.text)}
    />
  )
}
```

## Debugging Native Modules

### Common Issues

| Issue | Solution |
|-------|----------|
| Module not found | Run `npx pod-install` (iOS) or `./gradlew clean` (Android) |
| Method not found | Check method signature matches bridge declaration |
| Events not received | Ensure listener is added before module emits |
| Type mismatch | Verify types between native and JavaScript |

### Debug Commands

```bash
# iOS
xcrun simctl spawn booted log stream --level debug --predicate 'process == "MyApp"'

# Android
adb logcat *:S ReactNative:V ReactNativeJS:V MyModule:V

# Rebuild
npx react-native run-android
npx react-native run-ios
```

## Best Practices

1. **Type Safety**: Always define TypeScript interfaces
2. **Error Handling**: Use proper reject/resolve in promises
3. **Thread Safety**: Offload heavy work to background threads
4. **Memory Management**: Clean up listeners and references
5. **Documentation**: Document all native methods and events
6. **Testing**: Test both success and error cases
7. **Version Compatibility**: Specify minimum platform versions

---

**Remember**: Native modules increase complexity. Always check if a library exists before creating your own. For Expo projects, use Expo modules instead of direct native code when possible.
