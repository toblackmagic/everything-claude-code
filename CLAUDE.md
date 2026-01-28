# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Everything Claude Code** is a comprehensive Claude Code plugin and configuration repository providing production-ready agents, skills, hooks, commands, and rules evolved from an Anthropic hackathon winner's 10+ months of intensive daily use.

This is a **configuration repository** - not a traditional application with build/run commands. The "code" consists of Markdown agents/skills/commands, JSON hooks, and Node.js utility scripts.

## Running Tests

```bash
# Run all tests
node tests/run-all.js

# Run individual test files
node tests/lib/utils.test.js
node tests/lib/package-manager.test.js
node tests/hooks/hooks.test.js
```

## Repository Architecture

### Plugin-Based Structure

The repository is organized as a Claude Code plugin with modular components:

```
everything-claude-code/
├── agents/          # Specialized subagents for delegation
├── skills/          # Workflow definitions and domain knowledge
├── commands/        # Slash commands for quick execution
├── rules/           # Always-follow guidelines (manual install)
├── hooks/           # Trigger-based automations (JSON config)
├── scripts/         # Cross-platform Node.js utilities
└── .claude-plugin/  # Plugin and marketplace manifests
```

### Core Architectural Patterns

1. **Agent-Based Delegation** - Specialized agents handle specific domains (TDD, security, architecture, code review)
2. **Instinct-Based Learning** - Continuous Learning v2 uses atomic "instincts" with confidence scoring (0.3-0.9)
3. **Hook-Driven Automation** - PreToolUse/PostToolUse hooks provide 100% reliable session observation
4. **Modular Rules System** - Rules are split by domain (security, coding-style, testing, git-workflow, agents, performance)

### Continuous Learning v2 Architecture

The learning system observes sessions via hooks and creates atomic instincts:

- **Observation**: Hooks capture prompts + tool use (PreToolUse/PostToolUse)
- **Pattern Detection**: Background agent (Haiku) analyzes observations.jsonl
- **Instinct Creation**: Atomic behaviors with confidence scores
- **Evolution**: Related instincts cluster into skills/commands/agents via `/evolve`

Commands: `/instinct-status`, `/instinct-import`, `/instinct-export`, `/evolve`

### Key Components

**agents/** - Specialized subagents with defined scope:
- `planner.md` - Feature implementation planning
- `architect.md` - System design decisions
- `tdd-guide.md` - Test-driven development enforcement
- `code-reviewer.md` - Quality and security review for backend/general code
- `frontend-reviewer.md` - React/React Native shared patterns review (hooks, TypeScript, components, performance, security)
- `rn-reviewer.md` - React Native-specific issues (Platform API, FlatList, native modules, AsyncStorage)
- `security-reviewer.md` - Vulnerability analysis
- `build-error-resolver.md` - Build error debugging
- `e2e-runner.md` - Playwright E2E testing
- `go-reviewer.md`, `go-build-resolver.md` - Go-specific agents

**skills/** - Workflow definitions and domain knowledge:
- `continuous-learning-v2/` - Instinct-based learning system
- `tdd-workflow/` - TDD methodology
- `coding-standards/` - Language best practices
- `backend-patterns/`, `frontend-patterns/`, `golang-patterns/` - Framework patterns
- `react-native-patterns/` - React Native platform compatibility, navigation, native modules
- `security-review/` - Security checklists
- `iterative-retrieval/` - Progressive context refinement

**commands/** - Slash commands:
- `/tdd` - TDD workflow execution
- `/code-review` - Quality review automation for backend/general code
- `/frontend-review` - React/React Native shared patterns review
- `/plan` - Implementation planning
- `/build-fix` - Build error resolution
- `/go-review`, `/go-test` - Go-specific commands
- `/rn-review`, `/rn-test`, `/rn-build` - React Native-specific commands
- `/skill-create` - Generate skills from git history
- `/instinct-*`, `/evolve` - Instinct management

**rules/** - Always-follow guidelines (must be manually installed to ~/.claude/rules/):
- `security.md` - Mandatory security checks
- `coding-style.md` - Immutability principle, file organization
- `testing.md` - 80% coverage requirement, TDD mandatory
- `git-workflow.md` - Conventional commits, PR process
- `agents.md` - When to delegate to subagents
- `performance.md` - Model selection, context management

## Core Development Principles

### Immutability (CRITICAL)

ALWAYS create new objects, NEVER mutate:
```javascript
// WRONG: Mutation
function updateUser(user, name) {
  user.name = name  // MUTATION!
  return user
}

// CORRECT: Immutability
function updateUser(user, name) {
  return { ...user, name }
}
```

### File Organization

MANY SMALL FILES > FEW LARGE FILES:
- 200-400 lines typical, 800 max
- Organize by feature/domain, not by type
- Extract utilities from large components

### Testing Requirements

- **80% minimum test coverage** (Unit + Integration + E2E)
- **TDD mandatory**: Write tests first (RED) → Implement (GREEN) → Refactor (IMPROVE)
- Use `tdd-guide` agent proactively for new features

### Security Protocol

If security issue found:
1. STOP immediately
2. Use `security-reviewer` agent
3. Fix CRITICAL issues before continuing
4. Rotate any exposed secrets

### Agent Delegation Rules

Use agents proactively WITHOUT waiting for user prompt:
- Complex features → `planner` agent
- Code just written → `code-reviewer` agent
- Bug fix/new feature → `tdd-guide` agent
- Architectural decision → `architect` agent

## Cross-Platform Scripts

All hooks and scripts are written in Node.js for Windows/macOS/Linux compatibility:

**scripts/lib/** - Shared utilities:
- `utils.js` - Cross-platform file/path/system utilities
- `package-manager.js` - Package manager detection (npm/pnpm/yarn/bun)

**scripts/hooks/** - Hook implementations:
- `session-start.js` - Load context on session start
- `session-end.js` - Save state on session end
- `pre-compact.js` - Pre-compaction state saving
- `suggest-compact.js` - Strategic compaction suggestions
- `evaluate-session.js` - Extract patterns from sessions

## Package Manager Detection

The plugin auto-detects preferred package manager with priority:
1. Environment variable: `CLAUDE_PACKAGE_MANAGER`
2. Project config: `.claude/package-manager.json`
3. package.json `packageManager` field
4. Lock file detection
5. Global config: `~/.claude/package-manager.json`
6. Fallback to first available

## Git Workflow

- **Conventional commits**: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`
- **Never commit to main directly**
- **PRs require review** - Analyze full commit history, not just latest
- Use `/skill-create` to generate skills from git history

## Installation Notes

**Rules must be installed manually** - Claude Code plugin system does not support distributing `rules` via plugins. Users must copy rules to `~/.claude/rules/` or project `.claude/rules/`.

## Context Window Management

Critical: Don't enable all MCPs at once. Keep:
- 20-30 MCPs configured
- Under 10 enabled per project
- Under 80 tools active
