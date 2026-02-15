"""
Agent Orchestrator for Claude Security Reviewer Enterprise
Coordinates multiple AI agents for parallel and sequential security analysis.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from abc import ABC, abstractmethod
import time
import logging

logger = logging.getLogger(__name__)


class AgentModel(Enum):
    """Available agent models"""
    HAIKU = "claude-3-5-haiku-20241022"
    SONNET = "claude-sonnet-4-5-20250929"
    OPUS = "claude-opus-4-5-20251101"
    GPT4 = "gpt-4"
    GPT4O = "gpt-4o"


class AgentRole(Enum):
    """Agent role categories"""
    SECURITY_ANALYZER = "security_analyzer"
    FALSE_POSITIVE_FILTER = "false_positive_filter"
    COMPLIANCE_CHECKER = "compliance_checker"
    BUG_DETECTOR = "bug_detector"
    VALIDATOR = "validator"
    CUSTOM = "custom"


@dataclass
class Task:
    """Task to be executed by an agent"""
    id: str
    type: str
    description: str
    context: Dict[str, Any]
    priority: int = 100
    timeout_seconds: int = 300
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.type,
            'description': self.description,
            'context': self.context,
            'priority': self.priority
        }


@dataclass
class AgentResult:
    """Result from an agent execution"""
    agent_name: str
    task_id: str
    success: bool
    output: Any
    error: Optional[str] = None
    execution_time: float = 0.0
    tokens_used: int = 0
    cost: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'agent_name': self.agent_name,
            'task_id': self.task_id,
            'success': self.success,
            'output': self.output,
            'error': self.error,
            'execution_time': self.execution_time,
            'tokens_used': self.tokens_used,
            'cost': self.cost,
            'metadata': self.metadata
        }


@dataclass
class ValidatedFinding:
    """Security finding that has been validated by multiple agents"""
    finding: Dict[str, Any]
    confidence: float
    validation_results: List[AgentResult]
    consensus_score: float
    final_severity: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding': self.finding,
            'confidence': self.confidence,
            'validation_results': [r.to_dict() for r in self.validation_results],
            'consensus_score': self.consensus_score,
            'final_severity': self.final_severity
        }


class BaseAgent(ABC):
    """
    Base class for all agents.
    Agents are specialized AI workers that perform specific security analysis tasks.
    """
    
    def __init__(
        self,
        name: str,
        model: AgentModel,
        role: AgentRole,
        system_prompt: str,
        allowed_tools: List[str],
        llm_client: Any
    ):
        """
        Initialize base agent.
        
        Args:
            name: Unique agent name
            model: Model to use (Haiku/Sonnet/Opus)
            role: Agent role category
            system_prompt: System prompt for the agent
            allowed_tools: List of tools this agent can use
            llm_client: LLM client for API calls
        """
        self.name = name
        self.model = model
        self.role = role
        self.system_prompt = system_prompt
        self.allowed_tools = allowed_tools
        self.llm_client = llm_client
        self.execution_count = 0
        self.success_count = 0
        self.total_execution_time = 0.0
    
    @abstractmethod
    async def execute(self, task: Task) -> AgentResult:
        """
        Execute a task.
        
        Args:
            task: Task to execute
            
        Returns:
            Agent result with findings or analysis
        """
        pass
    
    async def safe_execute(self, task: Task) -> AgentResult:
        """
        Execute task with error handling and metrics tracking.
        
        Args:
            task: Task to execute
            
        Returns:
            Agent result
        """
        self.execution_count += 1
        start_time = time.time()
        
        try:
            result = await asyncio.wait_for(
                self.execute(task),
                timeout=task.timeout_seconds
            )
            self.success_count += 1
            execution_time = time.time() - start_time
            self.total_execution_time += execution_time
            result.execution_time = execution_time
            return result
            
        except asyncio.TimeoutError:
            execution_time = time.time() - start_time
            self.total_execution_time += execution_time
            return AgentResult(
                agent_name=self.name,
                task_id=task.id,
                success=False,
                output=None,
                error=f"Task timed out after {task.timeout_seconds}s",
                execution_time=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.total_execution_time += execution_time
            logger.error(f"Agent {self.name} failed: {e}", exc_info=True)
            return AgentResult(
                agent_name=self.name,
                task_id=task.id,
                success=False,
                output=None,
                error=str(e),
                execution_time=execution_time
            )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get agent execution statistics"""
        return {
            'executions': self.execution_count,
            'successes': self.success_count,
            'failures': self.execution_count - self.success_count,
            'total_time': self.total_execution_time,
            'avg_time': self.total_execution_time / max(1, self.execution_count)
        }


class AgentOrchestrator:
    """
    Coordinates multiple agents for complex security analysis workflows.
    
    Features:
    - Parallel agent execution
    - Sequential workflows with validation
    - Agent result aggregation
    - Confidence scoring
    - Load balancing across models
    """
    
    def __init__(self, hook_manager=None):
        """
        Initialize orchestrator.
        
        Args:
            hook_manager: Optional hook manager for event handling
        """
        self.hook_manager = hook_manager
        self.agent_registry: Dict[str, BaseAgent] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self.results_cache: Dict[str, AgentResult] = {}
    
    def register_agent(self, agent: BaseAgent) -> bool:
        """
        Register an agent.
        
        Args:
            agent: Agent instance to register
            
        Returns:
            True if successful
        """
        if agent.name in self.agent_registry:
            logger.warning(f"Agent {agent.name} already registered")
            return False
        
        self.agent_registry[agent.name] = agent
        logger.info(f"Registered agent: {agent.name} (model={agent.model.value}, role={agent.role.value})")
        return True
    
    def unregister_agent(self, agent_name: str) -> bool:
        """Unregister an agent"""
        if agent_name not in self.agent_registry:
            return False
        
        del self.agent_registry[agent_name]
        return True
    
    def get_agent(self, agent_name: str) -> Optional[BaseAgent]:
        """Get a specific agent"""
        return self.agent_registry.get(agent_name)
    
    def get_agents_by_role(self, role: AgentRole) -> List[BaseAgent]:
        """Get all agents with a specific role"""
        return [
            agent for agent in self.agent_registry.values()
            if agent.role == role
        ]
    
    async def execute_agent(
        self,
        agent_name: str,
        task: Task
    ) -> AgentResult:
        """
        Execute a single agent.
        
        Args:
            agent_name: Name of agent to execute
            task: Task to execute
            
        Returns:
            Agent result
        """
        agent = self.agent_registry.get(agent_name)
        if not agent:
            return AgentResult(
                agent_name=agent_name,
                task_id=task.id,
                success=False,
                output=None,
                error=f"Agent {agent_name} not found"
            )
        
        return await agent.safe_execute(task)
    
    async def execute_parallel_agents(
        self,
        agent_names: List[str],
        tasks: List[Task],
        max_concurrency: int = 10
    ) -> List[AgentResult]:
        """
        Execute multiple agents in parallel.
        
        Args:
            agent_names: List of agent names to execute
            tasks: List of tasks (one per agent)
            max_concurrency: Maximum concurrent executions
            
        Returns:
            List of agent results
        """
        if len(agent_names) != len(tasks):
            # If tasks list is shorter, duplicate the first task for all agents
            if len(tasks) == 1:
                tasks = tasks * len(agent_names)
            else:
                raise ValueError("Number of agents and tasks must match")
        
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def execute_with_semaphore(agent_name: str, task: Task):
            async with semaphore:
                return await self.execute_agent(agent_name, task)
        
        # Create tasks for parallel execution
        execution_tasks = [
            execute_with_semaphore(agent_name, task)
            for agent_name, task in zip(agent_names, tasks)
        ]
        
        # Execute all agents in parallel
        results = await asyncio.gather(*execution_tasks, return_exceptions=True)
        
        # Handle exceptions
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Agent {agent_names[i]} raised exception: {result}")
                final_results.append(AgentResult(
                    agent_name=agent_names[i],
                    task_id=tasks[i].id,
                    success=False,
                    output=None,
                    error=str(result)
                ))
            else:
                final_results.append(result)
        
        return final_results
    
    async def execute_sequential_with_validation(
        self,
        primary_agent_names: List[str],
        validator_agent_names: List[str],
        context: Dict[str, Any],
        confidence_threshold: float = 0.7
    ) -> List[ValidatedFinding]:
        """
        Execute primary agents, then validate findings with validator agents.
        
        This is the core workflow for high-confidence security analysis:
        1. Run primary agents in parallel to find potential issues
        2. Extract findings from results
        3. For each finding, run validator agents in parallel
        4. Calculate confidence score based on validation consensus
        5. Filter findings below confidence threshold
        
        Args:
            primary_agent_names: Names of primary security analyzer agents
            validator_agent_names: Names of validation agents
            context: Shared context (code, PR data, etc.)
            confidence_threshold: Minimum confidence to keep finding (0.0-1.0)
            
        Returns:
            List of validated findings above confidence threshold
        """
        logger.info(f"Starting sequential validation workflow: {len(primary_agent_names)} primary agents, {len(validator_agent_names)} validators")
        
        # Step 1: Execute primary agents in parallel
        primary_tasks = [
            Task(
                id=f"primary_{i}",
                type="security_analysis",
                description=f"Security analysis by {agent_name}",
                context=context
            )
            for i, agent_name in enumerate(primary_agent_names)
        ]
        
        primary_results = await self.execute_parallel_agents(
            primary_agent_names,
            primary_tasks
        )
        
        # Step 2: Extract all findings from primary results
        all_findings = []
        for result in primary_results:
            if result.success and result.output:
                findings = result.output.get('findings', [])
                all_findings.extend(findings)
        
        logger.info(f"Primary agents found {len(all_findings)} potential findings")
        
        if not all_findings:
            return []
        
        # Step 3: Validate each finding with validator agents
        validated_findings = []
        
        for finding_idx, finding in enumerate(all_findings):
            # Create validation context with the finding
            validation_context = {
                **context,
                'finding': finding,
                'finding_index': finding_idx
            }
            
            # Create validation tasks
            validation_tasks = [
                Task(
                    id=f"validate_{finding_idx}_{i}",
                    type="finding_validation",
                    description=f"Validate finding {finding_idx}",
                    context=validation_context,
                    timeout_seconds=120  # Shorter timeout for validation
                )
                for i in range(len(validator_agent_names))
            ]
            
            # Execute validators in parallel for this finding
            validation_results = await self.execute_parallel_agents(
                validator_agent_names,
                validation_tasks
            )
            
            # Step 4: Calculate confidence score
            confidence, consensus = self._calculate_confidence(
                finding,
                validation_results
            )
            
            # Step 5: Filter by confidence threshold
            if confidence >= confidence_threshold:
                validated_finding = ValidatedFinding(
                    finding=finding,
                    confidence=confidence,
                    validation_results=validation_results,
                    consensus_score=consensus,
                    final_severity=finding.get('severity', 'MEDIUM')
                )
                validated_findings.append(validated_finding)
                logger.info(f"Finding {finding_idx} validated with confidence {confidence:.2f}")
            else:
                logger.debug(f"Finding {finding_idx} filtered out (confidence {confidence:.2f} < {confidence_threshold})")
        
        logger.info(f"Validation complete: {len(validated_findings)}/{len(all_findings)} findings above confidence threshold")
        
        return validated_findings
    
    def _calculate_confidence(
        self,
        finding: Dict[str, Any],
        validation_results: List[AgentResult]
    ) -> Tuple[float, float]:
        """
        Calculate confidence score for a finding based on validator consensus.
        
        Args:
            finding: Security finding to score
            validation_results: Results from validator agents
            
        Returns:
            Tuple of (confidence_score, consensus_score)
        """
        if not validation_results:
            return 0.0, 0.0
        
        # Count validators that confirmed the finding
        confirmations = 0
        total_validators = 0
        confidence_scores = []
        
        for result in validation_results:
            if result.success and result.output:
                total_validators += 1
                
                # Check if validator confirmed the finding
                keep_finding = result.output.get('keep_finding', False)
                validator_confidence = result.output.get('confidence_score', 0.5)
                
                if keep_finding:
                    confirmations += 1
                    confidence_scores.append(validator_confidence / 10.0)  # Normalize to 0-1
                else:
                    confidence_scores.append(0.0)
        
        if total_validators == 0:
            return 0.0, 0.0
        
        # Consensus score: percentage of validators that confirmed
        consensus = confirmations / total_validators
        
        # Confidence score: weighted average including:
        # - Consensus (60% weight)
        # - Average validator confidence (30% weight)
        # - Severity bonus (10% weight)
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        severity = finding.get('severity', 'MEDIUM').upper()
        severity_bonus = {'HIGH': 0.1, 'MEDIUM': 0.05, 'LOW': 0.0}.get(severity, 0.0)
        
        confidence = (
            consensus * 0.6 +
            avg_confidence * 0.3 +
            severity_bonus * 0.1
        )
        
        # Cap at 1.0
        confidence = min(1.0, confidence)
        
        return confidence, consensus
    
    async def execute_workflow(
        self,
        workflow: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a complete multi-step workflow.
        
        Args:
            workflow: Workflow definition with steps
            
        Returns:
            Workflow results
        """
        # TODO: Implement workflow engine
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for all agents"""
        return {
            'total_agents': len(self.agent_registry),
            'agents_by_role': {
                role.value: len(self.get_agents_by_role(role))
                for role in AgentRole
            },
            'agent_stats': {
                name: agent.get_stats()
                for name, agent in self.agent_registry.items()
            }
        }
    
    def clear_stats(self):
        """Clear statistics for all agents"""
        for agent in self.agent_registry.values():
            agent.execution_count = 0
            agent.success_count = 0
            agent.total_execution_time = 0.0
