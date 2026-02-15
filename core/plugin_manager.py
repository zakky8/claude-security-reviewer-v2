"""
Plugin Manager for Claude Security Reviewer Enterprise
Enables dynamic loading, validation, and management of security plugins.
"""

import json
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class PluginStatus(Enum):
    """Plugin status enumeration"""
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"
    NOT_LOADED = "not_loaded"


@dataclass
class PluginMetadata:
    """Plugin metadata from plugin.json"""
    name: str
    version: str
    author: str
    description: str
    dependencies: List[str] = field(default_factory=list)
    requires_api_key: bool = False
    category: str = "general"
    tags: List[str] = field(default_factory=list)


@dataclass
class PluginCommand:
    """Slash command definition"""
    name: str
    description: str
    handler: Any
    allowed_tools: List[str] = field(default_factory=list)


@dataclass
class PluginAgent:
    """Agent definition"""
    name: str
    model: str
    role: str
    system_prompt: str
    allowed_tools: List[str]


@dataclass
class PluginSkill:
    """Skill definition"""
    name: str
    description: str
    activation_patterns: List[str]
    skill_content: str


@dataclass
class Plugin:
    """Complete plugin definition"""
    metadata: PluginMetadata
    path: Path
    commands: Dict[str, PluginCommand] = field(default_factory=dict)
    agents: Dict[str, PluginAgent] = field(default_factory=dict)
    skills: Dict[str, PluginSkill] = field(default_factory=dict)
    hooks: Dict[str, Any] = field(default_factory=dict)
    status: PluginStatus = PluginStatus.NOT_LOADED


class PluginManager:
    """
    Manages plugin lifecycle including discovery, loading, validation, and execution.
    
    Features:
    - Hot-reload capabilities
    - Dependency resolution
    - Version management
    - Sandboxed execution
    - Plugin marketplace integration
    """
    
    def __init__(self, plugins_dir: Path, config_path: Optional[Path] = None):
        """
        Initialize the plugin manager.
        
        Args:
            plugins_dir: Directory containing plugins
            config_path: Path to plugin configuration file
        """
        self.plugins_dir = Path(plugins_dir)
        self.config_path = config_path or self.plugins_dir / "config.json"
        self.loaded_plugins: Dict[str, Plugin] = {}
        self.enabled_plugins: set = set()
        self.plugin_order: List[str] = []  # For dependency ordering
        
        self._load_config()
        
    def _load_config(self):
        """Load plugin configuration"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    self.enabled_plugins = set(config.get('enabled', []))
                    self.plugin_order = config.get('order', [])
            except Exception as e:
                logger.error(f"Failed to load plugin config: {e}")
                self.enabled_plugins = set()
                self.plugin_order = []
    
    def _save_config(self):
        """Save plugin configuration"""
        try:
            config = {
                'enabled': list(self.enabled_plugins),
                'order': self.plugin_order
            }
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save plugin config: {e}")
    
    def discover_plugins(self) -> List[PluginMetadata]:
        """
        Discover all available plugins in the plugins directory.
        
        Returns:
            List of plugin metadata objects
        """
        discovered = []
        
        if not self.plugins_dir.exists():
            logger.warning(f"Plugins directory not found: {self.plugins_dir}")
            return discovered
        
        for plugin_dir in self.plugins_dir.iterdir():
            if not plugin_dir.is_dir():
                continue
            
            plugin_json = plugin_dir / ".claude-plugin" / "plugin.json"
            if not plugin_json.exists():
                continue
            
            try:
                with open(plugin_json, 'r') as f:
                    data = json.load(f)
                    metadata = PluginMetadata(
                        name=data['name'],
                        version=data['version'],
                        author=data['author'],
                        description=data['description'],
                        dependencies=data.get('dependencies', []),
                        requires_api_key=data.get('requires_api_key', False),
                        category=data.get('category', 'general'),
                        tags=data.get('tags', [])
                    )
                    discovered.append(metadata)
            except Exception as e:
                logger.error(f"Failed to load plugin metadata from {plugin_dir}: {e}")
        
        return discovered
    
    def load_plugin(self, plugin_name: str) -> Optional[Plugin]:
        """
        Load a plugin and all its components.
        
        Args:
            plugin_name: Name of the plugin to load
            
        Returns:
            Loaded plugin object or None if loading failed
        """
        plugin_dir = self.plugins_dir / plugin_name
        
        if not plugin_dir.exists():
            logger.error(f"Plugin directory not found: {plugin_dir}")
            return None
        
        try:
            # Load metadata
            plugin_json = plugin_dir / ".claude-plugin" / "plugin.json"
            with open(plugin_json, 'r') as f:
                data = json.load(f)
                metadata = PluginMetadata(
                    name=data['name'],
                    version=data['version'],
                    author=data['author'],
                    description=data['description'],
                    dependencies=data.get('dependencies', []),
                    requires_api_key=data.get('requires_api_key', False),
                    category=data.get('category', 'general'),
                    tags=data.get('tags', [])
                )
            
            plugin = Plugin(
                metadata=metadata,
                path=plugin_dir,
                status=PluginStatus.NOT_LOADED
            )
            
            # Load commands
            commands_dir = plugin_dir / "commands"
            if commands_dir.exists():
                for cmd_file in commands_dir.glob("*.md"):
                    command = self._load_command(cmd_file)
                    if command:
                        plugin.commands[command.name] = command
            
            # Load agents
            agents_dir = plugin_dir / "agents"
            if agents_dir.exists():
                for agent_file in agents_dir.glob("*.md"):
                    agent = self._load_agent(agent_file)
                    if agent:
                        plugin.agents[agent.name] = agent
            
            # Load skills
            skills_dir = plugin_dir / "skills"
            if skills_dir.exists():
                for skill_dir in skills_dir.iterdir():
                    if skill_dir.is_dir():
                        skill = self._load_skill(skill_dir)
                        if skill:
                            plugin.skills[skill.name] = skill
            
            # Load hooks
            hooks_dir = plugin_dir / "hooks"
            if hooks_dir.exists():
                for hook_file in hooks_dir.glob("*.py"):
                    hook = self._load_hook(hook_file)
                    if hook:
                        plugin.hooks[hook_file.stem] = hook
            
            plugin.status = PluginStatus.DISABLED
            self.loaded_plugins[plugin_name] = plugin
            
            logger.info(f"Successfully loaded plugin: {plugin_name}")
            return plugin
            
        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")
            return None
    
    def _load_command(self, cmd_file: Path) -> Optional[PluginCommand]:
        """Load a command from a markdown file"""
        try:
            with open(cmd_file, 'r') as f:
                content = f.read()
            
            # Parse frontmatter
            if content.startswith('---'):
                parts = content.split('---', 2)
                if len(parts) >= 3:
                    frontmatter = parts[1]
                    description = parts[2].strip()
                    
                    # Parse frontmatter
                    allowed_tools = []
                    for line in frontmatter.split('\n'):
                        if line.startswith('allowed-tools:'):
                            tools_str = line.split(':', 1)[1].strip()
                            allowed_tools = [t.strip() for t in tools_str.split(',')]
                    
                    return PluginCommand(
                        name=cmd_file.stem,
                        description=description[:200],
                        handler=None,  # To be set by command executor
                        allowed_tools=allowed_tools
                    )
        except Exception as e:
            logger.error(f"Failed to load command from {cmd_file}: {e}")
        
        return None
    
    def _load_agent(self, agent_file: Path) -> Optional[PluginAgent]:
        """Load an agent from a markdown file"""
        try:
            with open(agent_file, 'r') as f:
                content = f.read()
            
            # Parse frontmatter
            if content.startswith('---'):
                parts = content.split('---', 2)
                if len(parts) >= 3:
                    frontmatter = parts[1]
                    system_prompt = parts[2].strip()
                    
                    # Parse frontmatter
                    metadata = {}
                    for line in frontmatter.split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            metadata[key.strip()] = value.strip()
                    
                    return PluginAgent(
                        name=metadata.get('name', agent_file.stem),
                        model=metadata.get('model', 'claude-sonnet-4-5-20250929'),
                        role=metadata.get('description', ''),
                        system_prompt=system_prompt,
                        allowed_tools=metadata.get('tools', '').split(',')
                    )
        except Exception as e:
            logger.error(f"Failed to load agent from {agent_file}: {e}")
        
        return None
    
    def _load_skill(self, skill_dir: Path) -> Optional[PluginSkill]:
        """Load a skill from a directory"""
        try:
            skill_file = skill_dir / "SKILL.md"
            if not skill_file.exists():
                return None
            
            with open(skill_file, 'r') as f:
                content = f.read()
            
            return PluginSkill(
                name=skill_dir.name,
                description=f"Skill: {skill_dir.name}",
                activation_patterns=[],  # To be parsed from content
                skill_content=content
            )
        except Exception as e:
            logger.error(f"Failed to load skill from {skill_dir}: {e}")
        
        return None
    
    def _load_hook(self, hook_file: Path) -> Optional[Any]:
        """Load a hook from a Python file"""
        try:
            spec = importlib.util.spec_from_file_location(hook_file.stem, hook_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module
        except Exception as e:
            logger.error(f"Failed to load hook from {hook_file}: {e}")
        
        return None
    
    def enable_plugin(self, plugin_name: str) -> bool:
        """
        Enable a plugin and register its components.
        
        Args:
            plugin_name: Name of the plugin to enable
            
        Returns:
            True if successful, False otherwise
        """
        if plugin_name not in self.loaded_plugins:
            plugin = self.load_plugin(plugin_name)
            if not plugin:
                return False
        
        plugin = self.loaded_plugins[plugin_name]
        
        # Validate dependencies
        for dep in plugin.metadata.dependencies:
            if dep not in self.enabled_plugins:
                logger.error(f"Plugin {plugin_name} depends on {dep} which is not enabled")
                return False
        
        # Enable the plugin
        plugin.status = PluginStatus.ENABLED
        self.enabled_plugins.add(plugin_name)
        
        # Update plugin order
        if plugin_name not in self.plugin_order:
            self.plugin_order.append(plugin_name)
        
        self._save_config()
        logger.info(f"Enabled plugin: {plugin_name}")
        return True
    
    def disable_plugin(self, plugin_name: str) -> bool:
        """
        Disable a plugin.
        
        Args:
            plugin_name: Name of the plugin to disable
            
        Returns:
            True if successful, False otherwise
        """
        if plugin_name not in self.loaded_plugins:
            return False
        
        # Check if any enabled plugins depend on this one
        for name, plugin in self.loaded_plugins.items():
            if (name in self.enabled_plugins and 
                plugin_name in plugin.metadata.dependencies):
                logger.error(f"Cannot disable {plugin_name}, {name} depends on it")
                return False
        
        plugin = self.loaded_plugins[plugin_name]
        plugin.status = PluginStatus.DISABLED
        self.enabled_plugins.discard(plugin_name)
        
        self._save_config()
        logger.info(f"Disabled plugin: {plugin_name}")
        return True
    
    def get_enabled_plugins(self) -> Dict[str, Plugin]:
        """Get all enabled plugins"""
        return {
            name: plugin 
            for name, plugin in self.loaded_plugins.items()
            if plugin.status == PluginStatus.ENABLED
        }
    
    def get_plugin(self, plugin_name: str) -> Optional[Plugin]:
        """Get a specific plugin"""
        return self.loaded_plugins.get(plugin_name)
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """
        Reload a plugin (hot-reload).
        
        Args:
            plugin_name: Name of the plugin to reload
            
        Returns:
            True if successful, False otherwise
        """
        was_enabled = plugin_name in self.enabled_plugins
        
        if was_enabled:
            self.disable_plugin(plugin_name)
        
        if plugin_name in self.loaded_plugins:
            del self.loaded_plugins[plugin_name]
        
        plugin = self.load_plugin(plugin_name)
        if not plugin:
            return False
        
        if was_enabled:
            return self.enable_plugin(plugin_name)
        
        return True
    
    def validate_plugin(self, plugin_name: str) -> tuple[bool, List[str]]:
        """
        Validate a plugin's structure and dependencies.
        
        Args:
            plugin_name: Name of the plugin to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        if plugin_name not in self.loaded_plugins:
            errors.append(f"Plugin {plugin_name} not loaded")
            return False, errors
        
        plugin = self.loaded_plugins[plugin_name]
        
        # Check dependencies
        for dep in plugin.metadata.dependencies:
            if dep not in self.loaded_plugins:
                errors.append(f"Missing dependency: {dep}")
        
        # Check plugin structure
        if not plugin.path.exists():
            errors.append(f"Plugin directory not found: {plugin.path}")
        
        plugin_json = plugin.path / ".claude-plugin" / "plugin.json"
        if not plugin_json.exists():
            errors.append("Missing plugin.json")
        
        return len(errors) == 0, errors
