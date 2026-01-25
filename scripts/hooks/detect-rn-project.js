#!/usr/bin/env node

/**
 * React Native Project Detection Hook
 *
 * Detects when the current project is a React Native project
 * and provides helpful context for development.
 */

const fs = require('fs');
const path = require('path');

// ANSI color codes
const colors = {
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  reset: '\x1b[0m',
  dim: '\x1b[2m'
};

function colorize(text, color) {
  return `${colors[color]}${text}${colors.reset}`;
}

function detectReactNativeProject() {
  const cwd = process.cwd();
  const packageJsonPath = path.join(cwd, 'package.json');

  // Check if package.json exists
  if (!fs.existsSync(packageJsonPath)) {
    return null;
  }

  let packageJson;
  try {
    packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  } catch (error) {
    return null;
  }

  // Get all dependencies
  const allDeps = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies
  };

  // React Native detection patterns
  const indicators = {
    isReactNative: !!allDeps['react-native'],
    isExpo: !!allDeps['expo'] || !!allDeps['expo-dev-client'],
    hasReactNavigation: !!allDeps['@react-navigation/native'],
    hasSafeArea: !!allDeps['react-native-safe-area-context'],
    hasScreens: !!allDeps['react-native-screens'],
    hasExpoRouter: !!allDeps['expo-router'],
  };

  // Check for project files
  const hasAppConfig = fs.existsSync(path.join(cwd, 'app.json')) ||
                       fs.existsSync(path.join(cwd, 'app.config.js'));
  const hasMetroConfig = fs.existsSync(path.join(cwd, 'metro.config.js'));
  const hasExpoDir = fs.existsSync(path.join(cwd, 'expo'));
  const hasIosDir = fs.existsSync(path.join(cwd, 'ios'));
  const hasAndroidDir = fs.existsSync(path.join(cwd, 'android'));

  // Determine project type
  const isExpoProject = indicators.isExpo || hasAppConfig || hasExpoDir;
  const isCliProject = indicators.isReactNative && (hasIosDir || hasAndroidDir) && !isExpoProject;
  const isReactNativeProject = isExpoProject || isCliProject;

  if (!isReactNativeProject) {
    return null;
  }

  // Detect React Native version
  let rnVersion = 'unknown';
  if (allDeps['react-native']) {
    rnVersion = allDeps['react-native'];
  }

  return {
    type: isExpoProject ? 'expo' : 'cli',
    version: rnVersion,
    platforms: {
      ios: hasIosDir,
      android: hasAndroidDir
    },
    features: indicators,
    hasMetroConfig
  };
}

function formatOutput(project) {
  const lines = [];

  lines.push('');
  lines.push(colorize('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'dim'));

  if (project.type === 'expo') {
    lines.push(colorize('⚡  Expo project detected', 'cyan'));
  } else {
    lines.push(colorize('⚡  React Native CLI project detected', 'cyan'));
  }

  lines.push('');
  lines.push(colorize(`   React Native: ${project.version}`, 'green'));

  if (project.type === 'expo') {
    lines.push(colorize('   Type: Managed Workflow', 'green'));
  } else {
    lines.push(colorize('   Type: Bare Workflow', 'green'));
  }

  if (project.platforms.ios || project.platforms.android) {
    lines.push('');
    lines.push(colorize('   Platforms:', 'yellow'));
    if (project.platforms.ios) {
      lines.push(colorize('     • iOS', 'green'));
    }
    if (project.platforms.android) {
      lines.push(colorize('     • Android', 'green'));
    }
  }

  // Feature suggestions
  const suggestions = [];
  if (!project.features.hasReactNavigation) {
    suggestions.push('Install @react-navigation/native for navigation');
  }
  if (!project.features.hasSafeArea) {
    suggestions.push('Install react-native-safe-area-context for safe areas');
  }
  if (!project.features.hasScreens && !project.features.hasExpoRouter) {
    suggestions.push('Install react-native-screens for optimized navigation');
  }

  if (suggestions.length > 0) {
    lines.push('');
    lines.push(colorize('   💡 Suggestions:', 'yellow'));
    suggestions.forEach(s => {
      lines.push(colorize(`     • ${s}`, 'dim'));
    });
  }

  // Command suggestions
  lines.push('');
  lines.push(colorize('   🔧 Available commands:', 'yellow'));
  lines.push(colorize('     /rn-init      - Initialize a new RN project', 'dim'));
  lines.push(colorize('     /rn-component - Create a new component', 'dim'));

  lines.push(colorize('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'dim'));
  lines.push('');

  return lines.join('\n');
}

function main() {
  const project = detectReactNativeProject();

  if (project) {
    console.log(formatOutput(project));
  }
}

// Only run when executed directly
if (require.main === module) {
  main();
}

module.exports = { detectReactNativeProject };
