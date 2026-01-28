---
description: Comprehensive React code review for components, hooks, TypeScript, and shared patterns. Invokes the frontend-reviewer agent.
---

# Frontend Code Review

This command invokes the **frontend-reviewer** agent for comprehensive React code review covering patterns shared by both web and mobile platforms.

## What This Command Does

1. **Identify React Changes**: Find modified `.tsx`, `.ts`, `.jsx`, `.js` files via `git diff`
2. **Run Static Analysis**: Execute ESLint, TypeScript, and tests
3. **Component Pattern Review**: Analyze props interfaces, component structure, file organization
4. **Hooks Review**: Check Rules of Hooks, dependency arrays, custom hook patterns, useEffect cleanup
5. **TypeScript Review**: Verify type definitions, generic components, event handling types
6. **Performance Review**: Analyze React.memo usage, useCallback/useMemo patterns, unnecessary re-renders
7. **Security Scan**: Check input validation, XSS prevention, HTTPS enforcement
8. **Generate Report**: Categorize issues by severity

## When to Use

Use `/frontend-review` when:
- After writing or modifying React components (web or mobile)
- Before committing React changes
- Reviewing pull requests with React code
- Onboarding to a React codebase
- Reviewing shared code between web and mobile projects

## Review Categories

### CRITICAL (Must Fix)
- Rules of Hooks violations (hooks inside conditions or loops)
- Missing useEffect cleanup (event listeners, timers, subscriptions)
- Missing dependency arrays in useEffect/useCallback
- XSS vulnerabilities (unescaped user input with dangerouslySetInnerHTML)
- Missing input validation
- Non-HTTPS API calls

### HIGH (Should Fix)
- Missing props interfaces
- Components using `any` types
- Large components (>300 lines)
- Poor component structure
- Improper error handling
- Missing TypeScript types for events

### MEDIUM (Consider)
- Missing React.memo for expensive components
- Missing useCallback/useMemo for expensive operations
- Inline functions causing re-renders
- console.log statements
- State mutations
- Missing test coverage

## Automated Checks Run

```bash
# TypeScript checking
npx tsc --noEmit

# Linting
npm run lint
# or
npx eslint . --ext .ts,.tsx,.js,.jsx

# Testing
npm test
```

## Example Usage

```text
User: /frontend-review

Agent:
# Frontend Code Review Report

## Files Reviewed
- src/components/UserCard.tsx (modified)
- src/hooks/useAuth.ts (modified)
- src/screens/ProfileScreen.tsx (modified)

## Static Analysis Results
✓ TypeScript: No errors
⚠️ ESLint: 3 warnings

## Issues Found

[CRITICAL] Missing useEffect Cleanup
File: src/hooks/useAuth.ts:28
Issue: Event listener added but never removed
```typescript
useEffect(() => {
  const subscription = authEmitter.addListener('change', handleAuthChange)
  // Missing: return () => subscription.remove()
}, [])
```
Fix: Add cleanup function
```typescript
useEffect(() => {
  const subscription = authEmitter.addListener('change', handleAuthChange)
  return () => subscription.remove()
}, [])
```

[HIGH] Missing Props Interface
File: src/components/UserCard.tsx:12
Issue: Component props not typed
```typescript
function UserCard({ name, email, onPress }) {
```
Fix: Add props interface
```typescript
interface UserCardProps {
  name: string
  email: string
  onPress: () => void
}

function UserCard({ name, email, onPress }: UserCardProps) {
```

[MEDIUM] Missing useCallback
File: src/screens/ProfileScreen.tsx:45
Issue: Function recreated on every render
```typescript
<ProfileCard onSave={() => saveProfile(data)} />
```
Fix: Use useCallback
```typescript
const handleSave = useCallback(() => {
  saveProfile(data)
}, [data, saveProfile])

<ProfileCard onSave={handleSave} />
```

## Summary
- CRITICAL: 1
- HIGH: 1
- MEDIUM: 1

Recommendation: ❌ Block merge until CRITICAL issue is fixed
```

## Approval Criteria

| Status | Condition |
|--------|-----------|
| ✅ Approve | No CRITICAL or HIGH issues |
| ⚠️ Warning | Only MEDIUM issues (merge with caution) |
| ❌ Block | CRITICAL or HIGH issues found |

## Integration with Other Commands

- Use `/frontend-review` for React code review (shared patterns)
- For React Native projects: Use `/rn-review` AFTER `/frontend-review` for platform-specific issues
- Use `/code-review` for non-frontend specific concerns
- Use `/go-review` for Go code
- Use `/tdd` before implementing new features

## Platform Coverage

This command reviews code for:
- **React Web** (Next.js, Vite, Create React App, etc.)
- **React Native** (shared hooks, components, utilities)
- **Shared packages** (monorepo code used by both web and mobile)

## Common Review Patterns

### Component Review Checklist
```markdown
- [ ] Props interface defined
- [ ] Component under 300 lines
- [ ] Clear separation of concerns
- [ ] No inline styles (web) or StyleSheet (RN) issues
```

### Hooks Review Checklist
```markdown
- [ ] No hooks inside conditions/loops
- [ ] All dependencies listed
- [ ] Custom hooks start with 'use'
- [ ] useEffect cleanup functions
- [ ] No stale closures
```

### TypeScript Review Checklist
```markdown
- [ ] No `any` types
- [ ] Event types properly defined
- [ ] Generic components used appropriately
- [ ] Type exports for reusable types
```

### Performance Review Checklist
```markdown
- [ ] Expensive components use React.memo
- [ ] Callbacks use useCallback
- [ ] Computations use useMemo
- [ ] No inline functions in render
```

## Related

- Agent: `agents/frontend-reviewer.md`
- Agent: `agents/rn-reviewer.md` (for RN-specific issues)
- Skills: `skills/frontend-patterns/`, `skills/react-native-patterns/`
