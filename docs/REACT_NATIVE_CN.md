# React Native 支持使用说明

## 概述

Everything Claude Code 现已完整支持 React Native 移动端开发，包括 Expo 和 React Native CLI 工作流，支持 iOS 和 Android 平台。

## 功能特性

### 📚 技能模块 (skills/react-native-patterns/)

| 模块 | 说明 |
|------|------|
| `skill.md` | 主技能定义，包含平台检测 |
| `components.md` | 组件模式、FlatList 优化、自定义 Hooks |
| `navigation.md` | React Navigation 类型安全导航设置 |
| `performance.md` | 性能优化策略 |
| `native-modules.md` | 原生模块桥接指南 |
| `testing.md` | Jest、React Native Testing Library、Detox 测试 |

### 🤖 移动开发代理 (agents/mobile-developer.md)

专门的 `mobile-developer` 代理处理 React Native 开发任务：
- 项目检测和验证
- 平台特定代码指导
- 原生模块集成
- 移动端性能优化

### ⚡ 命令

| 命令 | 说明 |
|------|------|
| `/rn-init` | 初始化新的 React Native 项目 |
| `/rn-component` | 生成带 TypeScript 的组件 |
| `/rn-navigation` | 设置类型安全的导航 |
| `/rn-test` | 配置测试基础设施 |

### 🔗 自动检测钩子

- 自动检测 React Native 项目
- 显示相关命令建议

## 快速开始

### 1. 自动检测

```bash
npm install
```

当检测到 React Native 项目时，会显示：

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚡  Expo project detected
   React Native: 0.72.x
   Type: Managed Workflow

   🔧 Available commands:
     /rn-init      - Initialize a new RN project
     /rn-component - Create a new component
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 2. 创建新项目

```
/rn-init MyApp
```

### 3. 创建组件

```
/rn-component Button
/rn-component UserCard --type memo
```

### 4. 设置导航

```
/rn-navigation --auth --bottom-tabs --deep-link
```

## 代码示例

### 平台特定代码

```typescript
import { Platform, StyleSheet } from 'react-native'

const styles = StyleSheet.create({
  container: {
    ...Platform.select({
      ios: { shadowColor: '#000' },
      android: { elevation: 4 },
    }),
  },
})
```

### 安全区域处理

```typescript
import { useSafeAreaInsets } from 'react-native-safe-area-context'

function Screen() {
  const insets = useSafeAreaInsets()
  return (
    <View style={{ paddingTop: insets.top }}>
      {/* 内容 */}
    </View>
  )
}
```

### 优化的列表

```typescript
<FlatList
  data={items}
  keyExtractor={(item) => item.id}
  renderItem={renderItem}
  removeClippedSubviews={true}
  maxToRenderPerBatch={10}
/>
```

## 运行测试

```bash
# 测试 React Native 支持
node tests/rn-support.test.js
```

## 更新的配置文件

| 文件 | 更新内容 |
|------|----------|
| `plugin.json` | 添加 React Native 关键词 |
| `marketplace.json` | 添加移动端标签 |
| `hooks.json` | 添加 RN 项目检测 |
| `code-reviewer.md` | 添加 RN 性能检查 |
| `security-reviewer.md` | 添加移动端安全检查 |

---

**详细文档请查看:** [REACT_NATIVE.md](./REACT_NATIVE.md)
