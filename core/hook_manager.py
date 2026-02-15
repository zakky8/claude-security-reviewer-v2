"""
Hook Manager for Claude Security Reviewer Enterprise
Enables event-driven architecture for security checks and workflow customization.
"""

import asyncio
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Awaitable
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


class HookType(Enum):
    """Hook execution points in the workflow"""
    PRE_TOOL_USE = "pretooluse"
    POST_TOOL_USE = "posttooluse"
    SESSION_START = "sessionstart"
    SESSION_END = "sessionend"
    STOP = "stop"
    USER_PROMPT_SUBMIT = "userpromptsubmit"
    FINDING_GENERATED = "findinggener"
    SCAN_START = "scanstart"
    SCAN_COMPLETE = "scancomplete"


@dataclass
class HookContext:
    """
    Context passed to hooks during execution.
    Contains all relevant information about the current operation.
    """
    hook_type: HookType
    session_id: str
    timestamp: float
    tool_name: Optional[str] = None
    tool_input: Optional[Dict[str, Any]] = None
    tool_output: Optional[Dict[str, Any]] = None
    user_prompt: Optional[str] = None
    finding: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value from metadata"""
        return self.metadata.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set value in metadata"""
        self.metadata[key] = value


@dataclass
class HookResult:
    """
    Result returned by a hook.
    """
    allow: bool = True
    message: Optional[str] = None
    suggestions: List[str] = field(default_factory=list)
    modified_input: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def should_block(self) -> bool:
        """Check if this hook result should block execution"""
        return not self.allow
    
    def has_message(self) -> bool:
        """Check if hook has a message to display"""
        return self.message is not None and len(self.message) > 0


class BaseHook(ABC):
    """
    Base class for all hooks.
    Hooks can intercept and modify workflow at various execution points.
    """
    
    def __init__(
        self,
        name: str,
        hook_type: HookType,
        priority: int = 100,
        enabled: bool = True,
        description: str = ""
    ):
        """
        Initialize base hook.
        
        Args:
            name: Unique hook name
            hook_type: Type of hook (when it executes)
            priority: Execution priority (lower = earlier, 0-1000)
            enabled: Whether hook is currently enabled
            description: Human-readable description
        """
        self.name = name
        self.hook_type = hook_type
        self.priority = priority
        self.enabled = enabled
        self.description = description
        self.execution_count = 0
        self.success_count = 0
        self.error_count = 0
    
    @abstractmethod
    async def execute(self, context: HookContext) -> HookResult:
        """
        Execute the hook logic.
        
        Args:
            context: Current execution context
            
        Returns:
            Hook result indicating whether to proceed
        """
        pass
    
    async def safe_execute(self, context: HookContext) -> HookResult:
        """
        Execute hook with error handling and metrics tracking.
        
        Args:
            context: Current execution context
            
        Returns:
            Hook result, or allow-all result if hook fails
        """
        if not self.enabled:
            return HookResult(allow=True)
        
        self.execution_count += 1
        
        try:
            result = await self.execute(context)
            self.success_count += 1
            return result
        except Exception as e:
            self.error_count += 1
            logger.error(f"Hook {self.name} failed: {e}", exc_info=True)
            # Fail open - allow execution to continue
            return HookResult(
                allow=True,
                message=f"Hook {self.name} encountered an error but execution continued",
                metadata={'error': str(e)}
            )
    
    def get_stats(self) -> Dict[str, int]:
        """Get hook execution statistics"""
        return {
            'executions': self.execution_count,
            'successes': self.success_count,
            'errors': self.error_count
        }


class HookManager:
    """
    Manages hook lifecycle and execution.
    
    Features:
    - Priority-based execution order
    - Async hook execution
    - Hook chaining
    - Error isolation
    - Performance metrics
    """
    
    def __init__(self):
        """Initialize the hook manager"""
        self.hooks: Dict[HookType, List[BaseHook]] = {
            hook_type: [] for hook_type in HookType
        }
        self.hook_registry: Dict[str, BaseHook] = {}
    
    def register_hook(self, hook: BaseHook) -> bool:
        """
        Register a new hook.
        
        Args:
            hook: Hook instance to register
            
        Returns:
            True if successful, False if hook name already exists
        """
        if hook.name in self.hook_registry:
            logger.warning(f"Hook {hook.name} already registered")
            return False
        
        self.hooks[hook.hook_type].append(hook)
        self.hook_registry[hook.name] = hook
        
        # Sort hooks by priority (lower priority = execute first)
        self.hooks[hook.hook_type].sort(key=lambda h: h.priority)
        
        logger.info(f"Registered hook: {hook.name} (type={hook.hook_type.value}, priority={hook.priority})")
        return True
    
    def unregister_hook(self, hook_name: str) -> bool:
        """
        Unregister a hook.
        
        Args:
            hook_name: Name of hook to unregister
            
        Returns:
            True if successful, False if hook not found
        """
        if hook_name not in self.hook_registry:
            return False
        
        hook = self.hook_registry[hook_name]
        self.hooks[hook.hook_type].remove(hook)
        del self.hook_registry[hook_name]
        
        logger.info(f"Unregistered hook: {hook_name}")
        return True
    
    def enable_hook(self, hook_name: str) -> bool:
        """Enable a hook"""
        if hook_name not in self.hook_registry:
            return False
        
        self.hook_registry[hook_name].enabled = True
        return True
    
    def disable_hook(self, hook_name: str) -> bool:
        """Disable a hook"""
        if hook_name not in self.hook_registry:
            return False
        
        self.hook_registry[hook_name].enabled = False
        return True
    
    def get_hook(self, hook_name: str) -> Optional[BaseHook]:
        """Get a specific hook by name"""
        return self.hook_registry.get(hook_name)
    
    def get_hooks_for_type(self, hook_type: HookType) -> List[BaseHook]:
        """Get all hooks of a specific type"""
        return [h for h in self.hooks[hook_type] if h.enabled]
    
    async def execute_hooks(
        self,
        hook_type: HookType,
        context: HookContext,
        stop_on_block: bool = True
    ) -> List[HookResult]:
        """
        Execute all hooks of a given type.
        
        Args:
            hook_type: Type of hooks to execute
            context: Execution context
            stop_on_block: Stop executing remaining hooks if one blocks
            
        Returns:
            List of hook results
        """
        hooks = self.get_hooks_for_type(hook_type)
        
        if not hooks:
            return []
        
        logger.debug(f"Executing {len(hooks)} hooks for {hook_type.value}")
        
        results = []
        
        for hook in hooks:
            result = await hook.safe_execute(context)
            results.append(result)
            
            # If hook blocks and we should stop, don't execute remaining hooks
            if stop_on_block and result.should_block():
                logger.info(f"Hook {hook.name} blocked execution, stopping hook chain")
                break
            
            # If hook modified input, update context for next hook
            if result.modified_input:
                context.tool_input = result.modified_input
        
        return results
    
    async def execute_pre_tool_use_hooks(
        self,
        session_id: str,
        tool_name: str,
        tool_input: Dict[str, Any]
    ) -> tuple[bool, Optional[str], List[str]]:
        """
        Execute PreToolUse hooks and determine if tool should execute.
        
        Args:
            session_id: Current session ID
            tool_name: Name of tool about to execute
            tool_input: Tool input parameters
            
        Returns:
            Tuple of (should_allow, message, suggestions)
        """
        import time
        
        context = HookContext(
            hook_type=HookType.PRE_TOOL_USE,
            session_id=session_id,
            timestamp=time.time(),
            tool_name=tool_name,
            tool_input=tool_input
        )
        
        results = await self.execute_hooks(
            HookType.PRE_TOOL_USE,
            context,
            stop_on_block=True
        )
        
        # Check if any hook blocked
        for result in results:
            if result.should_block():
                return False, result.message, result.suggestions
        
        return True, None, []
    
    async def execute_post_tool_use_hooks(
        self,
        session_id: str,
        tool_name: str,
        tool_input: Dict[str, Any],
        tool_output: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute PostToolUse hooks and potentially modify output.
        
        Args:
            session_id: Current session ID
            tool_name: Name of executed tool
            tool_input: Tool input parameters
            tool_output: Tool output
            
        Returns:
            Potentially modified tool output
        """
        import time
        
        context = HookContext(
            hook_type=HookType.POST_TOOL_USE,
            session_id=session_id,
            timestamp=time.time(),
            tool_name=tool_name,
            tool_input=tool_input,
            tool_output=tool_output
        )
        
        results = await self.execute_hooks(
            HookType.POST_TOOL_USE,
            context,
            stop_on_block=False  # Don't stop, process all post hooks
        )
        
        # Apply any output modifications
        modified_output = tool_output
        for result in results:
            if result.modified_input:
                modified_output = result.modified_input
        
        return modified_output
    
    def get_all_hooks(self) -> List[BaseHook]:
        """Get all registered hooks"""
        return list(self.hook_registry.values())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for all hooks"""
        stats = {
            'total_hooks': len(self.hook_registry),
            'enabled_hooks': sum(1 for h in self.hook_registry.values() if h.enabled),
            'hooks_by_type': {
                hook_type.value: len([h for h in hooks if h.enabled])
                for hook_type, hooks in self.hooks.items()
            },
            'hook_stats': {
                name: hook.get_stats()
                for name, hook in self.hook_registry.items()
            }
        }
        return stats
    
    def clear_stats(self):
        """Clear statistics for all hooks"""
        for hook in self.hook_registry.values():
            hook.execution_count = 0
            hook.success_count = 0
            hook.error_count = 0


# Convenience decorator for creating simple hooks
def hook(
    name: str,
    hook_type: HookType,
    priority: int = 100,
    description: str = ""
):
    """
    Decorator to create a hook from a function.
    
    Usage:
        @hook("my_hook", HookType.PRE_TOOL_USE, priority=50)
        async def my_hook_func(context: HookContext) -> HookResult:
            # Hook logic here
            return HookResult(allow=True)
    """
    def decorator(func: Callable[[HookContext], Awaitable[HookResult]]):
        class DecoratorHook(BaseHook):
            async def execute(self, context: HookContext) -> HookResult:
                return await func(context)
        
        return DecoratorHook(
            name=name,
            hook_type=hook_type,
            priority=priority,
            description=description
        )
    
    return decorator
