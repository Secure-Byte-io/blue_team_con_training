import json
import logging
import os
import argparse
import uuid
from neo4j import GraphDatabase
from typing import Dict, List, Optional

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)



# Performance tuning constants
DEFAULT_BATCH_SIZE = int(os.environ.get('GRAPH_BATCH_SIZE', '1000'))
DEFAULT_STREAM_CHUNK_SIZE = int(os.environ.get('GRAPH_STREAM_CHUNK_SIZE', '5000'))
LARGE_FILE_THRESHOLD = int(os.environ.get('LARGE_FILE_THRESHOLD', '50000'))  # Switch to streaming for files > 50k events
MEMORY_EFFICIENT_MODE = os.environ.get('MEMORY_EFFICIENT_MODE', 'auto').lower()  # 'auto', 'always', 'never'

# Sysmon Event ID to node type mapping (excluding Event ID 1 since Process nodes handle process creation)
SYSMON_EVENT_NODE_TYPES = {
    #'2': 'FileTimeChange',         # File creation time changed
    #'3': 'NetworkConnection',      # Network connection
    '4': 'SysmonStateChange',      # Sysmon service state changed
    '5': 'ProcessTermination',     # Process terminated
    '6': 'DriverLoad',             # Driver loaded
    #'7': 'ImageLoad',              # Image loaded
    #'8': 'RemoteThreadCreation',   # CreateRemoteThread
    #'9': 'RawAccessRead',          # RawAccessRead
    #'10': 'ProcessAccess',         # ProcessAccess
    '11': 'FileCreation',          # FileCreate
    '12': 'RegistryObjectChange',  # RegistryEvent (Object create and delete)
    '13': 'RegistryValueSet',      # RegistryEvent (Value Set)
    '14': 'RegistryRename',        # RegistryEvent (Key and Value Rename)
    '15': 'FileStreamCreation',    # FileCreateStreamHash
    '17': 'PipeCreation',          # PipeEvent (Pipe Created)
    '18': 'PipeConnection',        # PipeEvent (Pipe Connected)
    '19': 'WmiFilterDetection',    # WmiEvent (WmiEventFilter activity detected)
    '20': 'WmiConsumerDetection',  # WmiEvent (WmiEventConsumer activity detected)
    '21': 'WmiBindingDetection',   # WmiEvent (WmiEventConsumerToFilter detected)
    '22': 'DnsQuery',              # DNSEvent (DNS query)
    #'23': 'FileDeleteArchived',    # FileDelete (File Delete archived)
    #'24': 'ClipboardChange',       # ClipboardChange (New content in clipboard)
   # '25': 'ProcessTampering',      # ProcessTampering (Process image change)
    '26': 'FileDeleteDetection',   # FileDeleteDetected (File Delete logged)
}

# Sysmon Event ID to meaningful relationship mapping
SYSMON_EVENT_RELATIONSHIPS = {
    '1': 'SPAWNED',                # Process creation (handled separately)
    '2': 'CHANGED_FILE_TIME',      # File creation time changed
    '3': 'CONNECTED_TO',           # Network connection
    '4': 'CHANGED_SYSMON_STATE',   # Sysmon service state changed
    '5': 'TERMINATED',             # Process terminated
    '6': 'LOADED_DRIVER',          # Driver loaded
    '7': 'LOADED_IMAGE',           # Image loaded
    '8': 'CREATED_REMOTE_THREAD',  # CreateRemoteThread
    '9': 'READ_RAW_DISK',          # RawAccessRead
    '10': 'ACCESSED_PROCESS',      # ProcessAccess
    '11': 'CREATED_FILE',          # FileCreate
    '12': 'MODIFIED_REGISTRY',     # RegistryEvent (Object create and delete)
    '13': 'SET_REGISTRY_VALUE',    # RegistryEvent (Value Set)
    '14': 'RENAMED_REGISTRY',      # RegistryEvent (Key and Value Rename)
    '15': 'CREATED_FILE_STREAM',   # FileCreateStreamHash
    '17': 'CREATED_PIPE',          # PipeEvent (Pipe Created)
    '18': 'CONNECTED_PIPE',        # PipeEvent (Pipe Connected)
    '19': 'DETECTED_WMI_FILTER',   # WmiEvent (WmiEventFilter activity detected)
    '20': 'DETECTED_WMI_CONSUMER',  # WmiEvent (WmiEventConsumer activity detected)
    '21': 'DETECTED_WMI_BINDING',   # WmiEvent (WmiEventConsumerToFilter detected)
    '22': 'QUERIED_DNS',            # DNSEvent (DNS query)
    '23': 'ARCHIVED_DELETED_FILE',  # FileDelete (File Delete archived)
    '24': 'CHANGED_CLIPBOARD',     # ClipboardChange (New content in clipboard)
    '25': 'TAMPERED_PROCESS',      # ProcessTampering (Process image change)
    '26': 'DETECTED_FILE_DELETE',  # FileDeleteDetected (File Delete logged)
}


NEO4J_URI = os.environ.get('NEO4J_URI')
NEO4J_USERNAME = os.environ.get('NEO4J_USERNAME')
NEO4J_PASSWORD = os.environ.get('NEO4J_PASSWORD')

class Neo4jHandler:
    def __init__(self, uri: str, username: str, password: str):
        """
        Initialize Neo4j driver for on-premise installation.
        
        Args:
            uri: Neo4j connection URI (e.g., "neo4j://localhost:7687" or "bolt://localhost:7687")
            username: Neo4j username
            password: Neo4j password
        """
        # Configure driver with appropriate settings for on-premise installations
        driver_config = {
            'auth': (username, password),
            'max_connection_lifetime': 300,  # 5 minutes
            'max_connection_pool_size': 50,
            'connection_acquisition_timeout': 60,  # 60 seconds
            'encrypted': False  # Default to unencrypted for on-premise
        }
        
        # Auto-detect if SSL should be enabled based on URI scheme
        if uri.startswith(('neo4j+s://', 'bolt+s://')):
            driver_config['encrypted'] = True
            logger.info("SSL encryption enabled based on URI scheme")
        elif uri.startswith(('neo4j://', 'bolt://')):
            driver_config['encrypted'] = False
            logger.info("SSL encryption disabled for on-premise installation")
        
        try:
            self.driver = GraphDatabase.driver(uri, **driver_config)
            # Test the connection
            with self.driver.session() as session:
                session.run("RETURN 1 AS test").single()
            logger.info(f"Successfully connected to Neo4j on-premise instance at {uri}")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j at {uri}: {str(e)}")
            raise ConnectionError(f"Could not establish connection to Neo4j: {str(e)}")
    
    def close(self):
        if self.driver:
            self.driver.close()
    
    def create_indexes(self, session, submission_id: str) -> None:
        """Create indexes for better performance on large datasets"""
        submission_label = f"Submission_{submission_id.replace('-', '_')}" if submission_id else "Submission_unknown"
        
        try:
            # Create indexes for better performance
            # Note: Neo4j indexes work on node labels, not specific label combinations
            index_queries = [
                "CREATE INDEX IF NOT EXISTS FOR (p:Process) ON (p.processId, p.submissionId)",
                "CREATE INDEX IF NOT EXISTS FOR (p:Process) ON (p.processGuid)",
                "CREATE INDEX IF NOT EXISTS FOR (s:Submission) ON (s.submissionId)",
            ]
            
            for query in index_queries:
                session.run(query)
                
        except Exception as e:
            logger.warning(f"Could not create some indexes (they may already exist): {e}")
    
    def batch_create_processes(self, session, processes: List[Dict], submission_id: str) -> None:
        """Create multiple process nodes in a single batch operation"""
        if not processes:
            return
            
        submission_label = f"Submission_{submission_id.replace('-', '_')}" if submission_id else "Submission_unknown"
        
        query = f"""
        UNWIND $processes AS process
        MERGE (p:Process:{submission_label} {{processId: process.processId, submissionId: process.submissionId}})
        SET p.image = process.image,
            p.commandLine = process.commandLine,
            p.user = process.user,
            p.currentDirectory = process.currentDirectory,
            p.processGuid = process.processGuid,
            p.utcTime = process.utcTime,
            p.parentProcessId = process.parentProcessId,
            p.parentImage = process.parentImage,
            p.parentCommandLine = process.parentCommandLine,
            p.computer = process.computer
        """
        
        session.run(query, {'processes': processes})
    
    def batch_create_spawn_relationships(self, session, relationships: List[Dict], submission_id: str) -> None:
        """Create multiple SPAWNED relationships in a single batch operation"""
        if not relationships:
            return
            
        submission_label = f"Submission_{submission_id.replace('-', '_')}" if submission_id else "Submission_unknown"
        
        query = f"""
        UNWIND $relationships AS rel
        MATCH (parent:Process:{submission_label} {{processId: rel.parentProcessId, submissionId: rel.submissionId}})
        MATCH (child:Process:{submission_label} {{processId: rel.childProcessId, submissionId: rel.submissionId}})
        MERGE (parent)-[r:SPAWNED {{utcTime: rel.utcTime, submissionId: rel.submissionId}}]->(child)
        """
        
        session.run(query, {'relationships': relationships})
    
    def batch_create_sysmon_events(self, session, events_by_type: Dict[str, List[Dict]], submission_id: str) -> None:
        """Create multiple event nodes of the same type in batch operations"""
        submission_label = f"Submission_{submission_id.replace('-', '_')}" if submission_id else "Submission_unknown"
        
        for event_id, events in events_by_type.items():
            if not events:
                continue
                
            node_type = SYSMON_EVENT_NODE_TYPES.get(event_id, 'UnknownEvent')
            
            query = f"""
            UNWIND $events AS event
            CREATE (e:{node_type}:{submission_label} {{
                eventId: event.eventId,
                utcTime: event.utcTime,
                processGuid: event.processGuid,
                processId: event.processId,
                ruleName: event.ruleName,
                submissionId: event.submissionId,
                eventRecordId: event.eventRecordId,
                computer: event.computer,
                image: event.image,
                targetFilename: event.targetFilename,
                targetObject: event.targetObject,
                destinationHostname: event.destinationHostname,
                destinationIp: event.destinationIp,
                destinationPort: event.destinationPort,
                queryName: event.queryName,
                commandLine: event.commandLine,
                user: event.user
            }})
            """
            
            session.run(query, {'events': events})
    
    def batch_create_event_relationships(self, session, relationships_by_type: Dict[str, List[Dict]], submission_id: str) -> None:
        """Create multiple event relationships in batch operations"""
        submission_label = f"Submission_{submission_id.replace('-', '_')}" if submission_id else "Submission_unknown"
        
        for event_id, relationships in relationships_by_type.items():
            if not relationships:
                continue
                
            relationship_type = SYSMON_EVENT_RELATIONSHIPS.get(event_id, 'GENERATED')
            node_type = SYSMON_EVENT_NODE_TYPES.get(event_id, 'UnknownEvent')
            
            query = f"""
            UNWIND $relationships AS rel
            MATCH (p:Process:{submission_label} {{processId: rel.processId, submissionId: rel.submissionId}})
            MATCH (e:{node_type}:{submission_label} {{processId: rel.processId, eventId: rel.eventId, submissionId: rel.submissionId, eventRecordId: rel.eventRecordId}})
            MERGE (p)-[r:{relationship_type} {{eventId: rel.eventId, utcTime: rel.utcTime, submissionId: rel.submissionId}}]->(e)
            """
            
            session.run(query, {'relationships': relationships})
    
    def create_process_node(self, session, process_id: int, event_data: Dict) -> None:
        """Create or update a process node with submission_id as label"""
        submission_id = event_data.get('submission_id', '')
        # Create a safe label from submission_id by replacing hyphens with underscores
        submission_label = f"Submission_{submission_id.replace('-', '_')}" if submission_id else "Submission_unknown"
        
        query = f"""
        MERGE (p:Process:{submission_label} {{processId: $process_id, submissionId: $submission_id}})
        SET p.image = $image,
            p.commandLine = $command_line,
            p.user = $user,
            p.currentDirectory = $current_directory,
            p.processGuid = $process_guid,
            p.utcTime = $utc_time,
            p.computer = $computer
        RETURN p
        """
        
        parameters = {
            'process_id': process_id,
            'image': event_data.get('Image', ''),
            'command_line': event_data.get('CommandLine', ''),
            'user': event_data.get('User', ''),
            'current_directory': event_data.get('CurrentDirectory', ''),
            'process_guid': event_data.get('ProcessGuid', ''),
            'utc_time': event_data.get('UtcTime', ''),
            'computer': event_data.get('Computer', ''),
            'submission_id': submission_id
        }
        
        session.run(query, parameters)
    
    def create_spawn_relationship(self, session, parent_process_id: int, child_process_id: int, event_data: Dict) -> None:
        """Create SPAWNED relationship between parent and child processes"""
        submission_id = event_data.get('submission_id', '')
        submission_label = f"Submission_{submission_id.replace('-', '_')}" if submission_id else "Submission_unknown"
        
        query = f"""
        MATCH (parent:Process:{submission_label} {{processId: $parent_process_id, submissionId: $submission_id}})
        MATCH (child:Process:{submission_label} {{processId: $child_process_id, submissionId: $submission_id}})
        MERGE (parent)-[r:SPAWNED {{utcTime: $utc_time, submissionId: $submission_id}}]->(child)
        RETURN r
        """
        
        parameters = {
            'parent_process_id': parent_process_id,
            'child_process_id': child_process_id,
            'utc_time': event_data.get('UtcTime', ''),
            'submission_id': submission_id
        }
        
        session.run(query, parameters)
    
    def create_event_node_and_relationship(self, session, process_id: int, event_id: int, event_data: Dict) -> None:
        """Create event node and connect it to the process"""
        submission_id = event_data.get('submission_id', '')
        submission_label = f"Submission_{submission_id.replace('-', '_')}" if submission_id else "Submission_unknown"
        
        query = f"""
        MATCH (p:Process:{submission_label} {{processId: $process_id, submissionId: $submission_id}})
        CREATE (e:Event:{submission_label} {{
            eventId: $event_id,
            utcTime: $utc_time,
            processGuid: $process_guid,
            ruleName: $rule_name,
            submissionId: $submission_id,
            eventRecordId: $event_record_id,
            computer: $computer,
            targetFilename: $target_filename,
            image: $image
        }})
        CREATE (p)-[r:GENERATED {{eventId: $event_id, utcTime: $utc_time, submissionId: $submission_id}}]->(e)
        RETURN e, r
        """
        
        parameters = {
            'process_id': process_id,
            'event_id': event_id,
            'utc_time': event_data.get('UtcTime', ''),
            'process_guid': event_data.get('ProcessGuid', ''),
            'rule_name': event_data.get('RuleName', ''),
            'submission_id': submission_id,
            'event_record_id': event_data.get('EventRecordID', ''),
            'computer': event_data.get('Computer', ''),
            'target_filename': event_data.get('TargetFilename', ''),
            'image': event_data.get('Image', '')
        }
        
        session.run(query, parameters)
    
    def create_submission_node(self, session, submission_id: str, event_counts: Dict) -> None:
        """Create a submission root node to organize all data from this submission"""
        submission_label = f"Submission_{submission_id.replace('-', '_')}" if submission_id else "Submission_unknown"
        
        query = f"""
        MERGE (s:Submission:{submission_label} {{submissionId: $submission_id}})
        SET s.totalEvents = $total_events,
            s.eventCounts = $event_counts,
            s.processedAt = datetime()
        RETURN s
        """
        
        parameters = {
            'submission_id': submission_id,
            'total_events': sum(event_counts.values()),
            'event_counts': str(event_counts)  # Convert dict to string for Neo4j
        }
        
        session.run(query, parameters)
    
    def link_to_submission(self, session, submission_id: str) -> None:
        """Link all processes and events to the submission node"""
        submission_label = f"Submission_{submission_id.replace('-', '_')}" if submission_id else "Submission_unknown"
        
        # Link all processes to submission
        query = f"""
        MATCH (s:Submission:{submission_label} {{submissionId: $submission_id}})
        MATCH (p:Process:{submission_label} {{submissionId: $submission_id}})
        MERGE (s)-[r:CONTAINS_PROCESS]->(p)
        RETURN count(r) as linked_processes
        """
        session.run(query, {'submission_id': submission_id})
        
        # Link all generic events to submission (for backward compatibility)
        query = f"""
        MATCH (s:Submission:{submission_label} {{submissionId: $submission_id}})
        MATCH (e:Event:{submission_label} {{submissionId: $submission_id}})
        MERGE (s)-[r:CONTAINS_EVENT]->(e)
        RETURN count(r) as linked_events
        """
        session.run(query, {'submission_id': submission_id})
        
        # Link all specific Sysmon event types to submission
        for event_id, node_type in SYSMON_EVENT_NODE_TYPES.items():
            query = f"""
            MATCH (s:Submission:{submission_label} {{submissionId: $submission_id}})
            MATCH (e:{node_type}:{submission_label} {{submissionId: $submission_id}})
            MERGE (s)-[r:CONTAINS_{node_type.upper()}]->(e)
            RETURN count(r) as linked_{node_type.lower()}_events
            """
            session.run(query, {'submission_id': submission_id})
    
    def create_sysmon_event_node(self, session, event_id: str, event_data: Dict) -> None:
        """Create a specific Sysmon event node based on event ID mapping"""
        submission_id = event_data.get('submission_id', '')
        submission_label = f"Submission_{submission_id.replace('-', '_')}" if submission_id else "Submission_unknown"
        
        # Get the specific node type for this event ID
        node_type = SYSMON_EVENT_NODE_TYPES.get(str(event_id), 'UnknownEvent')
        
        query = f"""
        CREATE (e:{node_type}:{submission_label} {{
            eventId: $event_id,
            utcTime: $utc_time,
            processGuid: $process_guid,
            processId: $process_id,
            ruleName: $rule_name,
            submissionId: $submission_id,
            eventRecordId: $event_record_id,
            computer: $computer,
            image: $image,
            targetFilename: $target_filename,
            targetObject: $target_object,
            destinationHostname: $destination_hostname,
            destinationIp: $destination_ip,
            destinationPort: $destination_port,
            queryName: $query_name,
            commandLine: $command_line,
            user: $user
        }})
        RETURN e
        """
        
        parameters = {
            'event_id': event_id,
            'utc_time': event_data.get('UtcTime', ''),
            'process_guid': event_data.get('ProcessGuid', ''),
            'process_id': event_data.get('ProcessId', ''),
            'rule_name': event_data.get('RuleName', ''),
            'submission_id': submission_id,
            'event_record_id': event_data.get('EventRecordID', ''),
            'computer': event_data.get('Computer', ''),
            'image': event_data.get('Image', ''),
            'target_filename': event_data.get('TargetFilename', ''),
            'target_object': event_data.get('TargetObject', ''),
            'destination_hostname': event_data.get('DestinationHostname', ''),
            'destination_ip': event_data.get('DestinationIp', ''),
            'destination_port': event_data.get('DestinationPort', ''),
            'query_name': event_data.get('QueryName', ''),
            'command_line': event_data.get('CommandLine', ''),
            'user': event_data.get('User', '')
        }
        
        session.run(query, parameters)
    
    def create_sysmon_event_relationship(self, session, process_id: int, event_id: str, event_data: Dict) -> None:
        """Create a relationship between process and event based on event ID mapping"""
        submission_id = event_data.get('submission_id', '')
        submission_label = f"Submission_{submission_id.replace('-', '_')}" if submission_id else "Submission_unknown"
        
        # Get the specific relationship type for this event ID
        relationship_type = SYSMON_EVENT_RELATIONSHIPS.get(str(event_id), 'GENERATED')
        node_type = SYSMON_EVENT_NODE_TYPES.get(str(event_id), 'UnknownEvent')
        
        query = f"""
        MATCH (p:Process:{submission_label} {{processId: $process_id, submissionId: $submission_id}})
        MATCH (e:{node_type}:{submission_label} {{processId: $process_id, eventId: $event_id, submissionId: $submission_id}})
        MERGE (p)-[r:{relationship_type} {{eventId: $event_id, utcTime: $utc_time, submissionId: $submission_id}}]->(e)
        RETURN r
        """
        
        parameters = {
            'process_id': process_id,
            'event_id': event_id,
            'utc_time': event_data.get('UtcTime', ''),
            'submission_id': submission_id
        }
        
        session.run(query, parameters)

def parse_sysmon_events(file_path: str) -> List[Dict]:
    """Parse Sysmon events from JSON file (one event per line) - legacy method"""
    events = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if line:
                    try:
                        event = json.loads(line)
                        events.append(event)
                    except json.JSONDecodeError as e:
                        logger.error(f"Error parsing JSON on line {line_num}: {e}")
                        continue
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
    
    return events

def stream_sysmon_events(file_path: str, chunk_size: int = 1000):
    """Generator that yields chunks of events for memory-efficient processing"""
    chunk = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if line:
                    try:
                        event = json.loads(line)
                        chunk.append(event)
                        
                        # Yield chunk when it reaches the desired size
                        if len(chunk) >= chunk_size:
                            yield chunk
                            chunk = []
                            
                    except json.JSONDecodeError as e:
                        logger.error(f"Error parsing JSON on line {line_num}: {e}")
                        continue
            
            # Yield remaining events
            if chunk:
                yield chunk
                
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")

def count_events_in_file(file_path: str) -> int:
    """Count total number of events in file without loading into memory"""
    count = 0
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                if line.strip():
                    count += 1
    except Exception as e:
        logger.error(f"Error counting events in file {file_path}: {e}")
    return count

def process_large_dataset_streaming(file_path: str, neo4j_handler: Neo4jHandler, batch_size: int = 1000, stream_chunk_size: int = 5000, submission_id: str = None) -> Dict:
    """Process very large datasets using streaming with configurable batch sizes"""
    
    logger.info(f"Starting streaming processing with batch_size={batch_size}, stream_chunk_size={stream_chunk_size}")
    
    # Count total events for progress tracking
    total_events = count_events_in_file(file_path)
    logger.info(f"Total events to process: {total_events}")
    
    if total_events == 0:
        return {
            'events_processed': 0,
            'event_counts': {},
            'processing_time': 0
        }
    
    import time
    start_time = time.time()
    
    # Use provided submission_id or get from first event
    if not submission_id:
        with open(file_path, 'r', encoding='utf-8') as file:
            first_line = file.readline().strip()
            if first_line:
                try:
                    first_event = json.loads(first_line)
                    submission_id = first_event.get('submission_id', '')
                except json.JSONDecodeError:
                    logger.error("Could not parse first event to get submission_id")
                    return {'error': 'Invalid JSON format'}
    
    # Initialize tracking variables
    total_processed = 0
    global_event_counts = {}
    
    with neo4j_handler.driver.session() as session:
        # Create indexes for better performance
        if submission_id:
            neo4j_handler.create_indexes(session, submission_id)
            logger.info("Created database indexes")
    
    # Process file in streaming chunks
    for chunk_num, chunk in enumerate(stream_sysmon_events(file_path, stream_chunk_size), 1):
        logger.info(f"Processing stream chunk {chunk_num} ({len(chunk)} events, {total_processed + len(chunk)}/{total_events} total)")
        
        # Count event types in this chunk
        for event in chunk:
            event_id = event.get('Event', {}).get('System', {}).get('EventID')
            global_event_counts[event_id] = global_event_counts.get(event_id, 0) + 1
        
        # Process this chunk with batch operations
        process_events_to_graph_optimized(chunk, neo4j_handler, batch_size, submission_id)
        
        total_processed += len(chunk)
        logger.info(f"Completed chunk {chunk_num}. Progress: {total_processed}/{total_events} ({total_processed/total_events*100:.1f}%)")
    
    # Create submission node with final counts
    if submission_id and global_event_counts:
        with neo4j_handler.driver.session() as session:
            neo4j_handler.create_submission_node(session, submission_id, global_event_counts)
            neo4j_handler.link_to_submission(session, submission_id)
            logger.info(f"Created final submission node and linked all data")
    
    processing_time = time.time() - start_time
    logger.info(f"Streaming processing completed in {processing_time:.2f} seconds. Average: {total_processed/processing_time:.1f} events/sec")
    
    return {
        'events_processed': total_processed,
        'event_counts': global_event_counts,
        'processing_time': processing_time,
        'average_events_per_second': total_processed / processing_time if processing_time > 0 else 0
    }



def process_events_to_graph_optimized(events: List[Dict], neo4j_handler: Neo4jHandler, batch_size: int = 1000, submission_id: str = None) -> None:
    """Optimized batch processing of Sysmon events with chunking for large datasets"""
    
    # Use provided submission_id or get from first event
    if not submission_id:
        submission_id = events[0].get('submission_id', '') if events else ''
    
    # Count event types for the submission node
    event_counts = {}
    for event in events:
        event_id = event.get('Event', {}).get('System', {}).get('EventID')
        event_counts[event_id] = event_counts.get(event_id, 0) + 1
    
    logger.info(f"Processing {len(events)} events in batches of {batch_size}")
    
    with neo4j_handler.driver.session() as session:
        # Create indexes for better performance
        if submission_id:
            neo4j_handler.create_indexes(session, submission_id)
            
        # Create submission node first
        if submission_id:
            neo4j_handler.create_submission_node(session, submission_id, event_counts)
            logger.info(f"Created submission node for: {submission_id}")
        
        # Process events in chunks to manage memory
        for chunk_start in range(0, len(events), batch_size):
            chunk_end = min(chunk_start + batch_size, len(events))
            chunk = events[chunk_start:chunk_end]
            logger.info(f"Processing chunk {chunk_start//batch_size + 1}/{(len(events)-1)//batch_size + 1} ({chunk_start+1}-{chunk_end} events)")
            
            # Prepare batch data structures
            processes_to_create = []
            spawn_relationships = []
            events_by_type = {}
            relationships_by_type = {}
            all_process_ids = set()
            
            # Single pass: collect all data for batch operations
            for event in chunk:
                try:
                    event_system = event.get('Event', {}).get('System', {})
                    event_data = event.get('Event', {}).get('EventData', {})
                    event_id = event_system.get('EventID')
                    
                    # Add submission_id to event_data for reference
                    if submission_id:
                        event_data['submission_id'] = submission_id
                    event_data['EventRecordID'] = event_system.get('EventRecordID', '')
                    event_data['Computer'] = event_system.get('Computer', '')
                    
                    if event_id == 1:  # Process creation event
                        process_id = event_data.get('ProcessId')
                        parent_process_id = event_data.get('ParentProcessId')
                        
                        if process_id:
                            all_process_ids.add(process_id)
                            # Prepare child process data
                            process_data = {
                                'processId': process_id,
                                'submissionId': submission_id,
                                'image': event_data.get('Image', ''),
                                'commandLine': event_data.get('CommandLine', ''),
                                'user': event_data.get('User', ''),
                                'currentDirectory': event_data.get('CurrentDirectory', ''),
                                'processGuid': event_data.get('ProcessGuid', ''),
                                'utcTime': event_data.get('UtcTime', ''),
                                'parentProcessId': parent_process_id,
                                'parentImage': event_data.get('ParentImage', ''),
                                'parentCommandLine': event_data.get('ParentCommandLine', ''),
                                'computer': event_data.get('Computer', '')
                            }
                            processes_to_create.append(process_data)
                            
                            # Prepare parent process data if it exists
                            if parent_process_id:
                                all_process_ids.add(parent_process_id)
                                parent_data = {
                                    'processId': parent_process_id,
                                    'submissionId': submission_id,
                                    'image': event_data.get('ParentImage', ''),
                                    'commandLine': event_data.get('ParentCommandLine', ''),
                                    'user': event_data.get('ParentUser', ''),
                                    'currentDirectory': '',
                                    'processGuid': event_data.get('ParentProcessGuid', ''),
                                    'utcTime': event_data.get('UtcTime', ''),
                                    'parentProcessId': None,
                                    'parentImage': '',
                                    'parentCommandLine': '',
                                    'computer': event_data.get('Computer', '')
                                }
                                processes_to_create.append(parent_data)
                                
                                # Prepare spawn relationship
                                spawn_rel = {
                                    'parentProcessId': parent_process_id,
                                    'childProcessId': process_id,
                                    'submissionId': submission_id,
                                    'utcTime': event_data.get('UtcTime', '')
                                }
                                spawn_relationships.append(spawn_rel)
                    
                    elif event_id and str(event_id) in SYSMON_EVENT_NODE_TYPES:
                        # Prepare event data for batch creation
                        process_id = event_data.get('ProcessId')
                        if process_id:
                            str_event_id = str(event_id)
                            
                            if str_event_id not in events_by_type:
                                events_by_type[str_event_id] = []
                                relationships_by_type[str_event_id] = []
                            
                            # Prepare event node data
                            event_node_data = {
                                'eventId': str_event_id,
                                'utcTime': event_data.get('UtcTime', ''),
                                'processGuid': event_data.get('ProcessGuid', ''),
                                'processId': process_id,
                                'ruleName': event_data.get('RuleName', ''),
                                'submissionId': submission_id,
                                'eventRecordId': event_data.get('EventRecordID', ''),
                                'computer': event_data.get('Computer', ''),
                                'image': event_data.get('Image', ''),
                                'targetFilename': event_data.get('TargetFilename', ''),
                                'targetObject': event_data.get('TargetObject', ''),
                                'destinationHostname': event_data.get('DestinationHostname', ''),
                                'destinationIp': event_data.get('DestinationIp', ''),
                                'destinationPort': event_data.get('DestinationPort', ''),
                                'queryName': event_data.get('QueryName', ''),
                                'commandLine': event_data.get('CommandLine', ''),
                                'user': event_data.get('User', '')
                            }
                            events_by_type[str_event_id].append(event_node_data)
                            
                            # Prepare relationship data
                            rel_data = {
                                'processId': process_id,
                                'eventId': str_event_id,
                                'submissionId': submission_id,
                                'utcTime': event_data.get('UtcTime', ''),
                                'eventRecordId': event_data.get('EventRecordID', '')
                            }
                            relationships_by_type[str_event_id].append(rel_data)
                            
                except Exception as e:
                    logger.error(f"Error processing event in batch: {e}")
                    continue
            
            # Execute batch operations
            if processes_to_create:
                # Remove duplicates based on processId
                unique_processes = {}
                for proc in processes_to_create:
                    key = proc['processId']
                    if key not in unique_processes or (proc['image'] and not unique_processes[key]['image']):
                        unique_processes[key] = proc
                
                neo4j_handler.batch_create_processes(session, list(unique_processes.values()), submission_id)
                logger.info(f"Batch created {len(unique_processes)} unique processes")
            
            if spawn_relationships:
                # Remove duplicate spawn relationships
                unique_spawns = {}
                for rel in spawn_relationships:
                    key = (rel['parentProcessId'], rel['childProcessId'])
                    unique_spawns[key] = rel
                
                neo4j_handler.batch_create_spawn_relationships(session, list(unique_spawns.values()), submission_id)
                logger.info(f"Batch created {len(unique_spawns)} spawn relationships")
            
            if events_by_type:
                neo4j_handler.batch_create_sysmon_events(session, events_by_type, submission_id)
                total_events = sum(len(events) for events in events_by_type.values())
                logger.info(f"Batch created {total_events} event nodes across {len(events_by_type)} event types")
                
                neo4j_handler.batch_create_event_relationships(session, relationships_by_type, submission_id)
                total_relationships = sum(len(rels) for rels in relationships_by_type.values())
                logger.info(f"Batch created {total_relationships} event relationships")
        
        # Finally, link all nodes to the submission
        if submission_id:
            neo4j_handler.link_to_submission(session, submission_id)
            logger.info(f"Linked all nodes to submission: {submission_id}")

def process_events_to_graph(events: List[Dict], neo4j_handler: Neo4jHandler) -> None:
    """Backward compatibility wrapper - redirects to optimized version"""
    process_events_to_graph_optimized(events, neo4j_handler)




def process_data(log_file_path: str, submission_id: str, batch_size: int = None, stream_chunk_size: int = None, memory_mode: str = 'auto') -> dict:
    """Process log data from file and create graph structure"""
    neo4j_handler = None
    
    # Use provided values or defaults
    if batch_size is None:
        batch_size = DEFAULT_BATCH_SIZE
    if stream_chunk_size is None:
        stream_chunk_size = DEFAULT_STREAM_CHUNK_SIZE
    
    try:
        # Validate Neo4j credentials and connection details
        missing_vars = []
        if not NEO4J_URI:
            missing_vars.append("NEO4J_URI")
        if not NEO4J_USERNAME:
            missing_vars.append("NEO4J_USERNAME")
        if not NEO4J_PASSWORD:
            missing_vars.append("NEO4J_PASSWORD")
            
        if missing_vars:
            error_msg = f"Missing required Neo4j environment variables: {', '.join(missing_vars)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Validate URI format
        valid_schemes = ['neo4j://', 'bolt://', 'neo4j+s://', 'bolt+s://']
        if not any(NEO4J_URI.startswith(scheme) for scheme in valid_schemes):
            error_msg = f"Invalid Neo4j URI format: {NEO4J_URI}. Must start with one of: {', '.join(valid_schemes)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Check if log file exists
        if not os.path.exists(log_file_path):
            error_msg = f"Log file not found: {log_file_path}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)
        
        logger.info(f"Processing log file: {log_file_path}")
        logger.info(f"Submission ID: {submission_id}")
        
        # Initialize Neo4j connection
        logger.info("Connecting to Neo4j on-premise instance")
        try:
            neo4j_handler = Neo4jHandler(NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD)
        except ConnectionError as conn_error:
            logger.error(f"Neo4j connection failed: {str(conn_error)}")
            raise conn_error
        
        # Determine processing method based on file size and configuration
        logger.info("Analyzing file for optimal processing method")
        total_events = count_events_in_file(log_file_path)
        logger.info(f"File contains {total_events} events")
        
        if total_events == 0:
            logger.warning("No events found in the file")
            return {
                "message": "File processed but no events found",
                "submission_id": submission_id,
                "events_processed": 0
            }
        
        # Choose processing method (batch vs streaming)
        use_streaming = False
        
        if memory_mode == 'always':
            use_streaming = True
            logger.info("Using streaming mode (forced by memory_mode=always)")
        elif memory_mode == 'never':
            use_streaming = False
            logger.info("Using batch mode (forced by memory_mode=never)")
        else:  # auto mode
            use_streaming = total_events > LARGE_FILE_THRESHOLD
            mode_reason = f"File has {total_events} events ({'>' if use_streaming else '<='} {LARGE_FILE_THRESHOLD} threshold)"
            logger.info(f"Auto-selected {'streaming' if use_streaming else 'batch'} mode: {mode_reason}")
        
        # Process events and create graph structure
        if use_streaming:
            processing_method = "streaming"
            logger.info(f"Processing large dataset with streaming (batch_size={batch_size}, stream_chunk_size={stream_chunk_size})")
            result = process_large_dataset_streaming(
                log_file_path, 
                neo4j_handler, 
                batch_size=batch_size,
                stream_chunk_size=stream_chunk_size,
                submission_id=submission_id
            )
            
            if 'error' in result:
                logger.error(f"Streaming processing failed: {result['error']}")
                raise Exception(result['error'])
            
            events_processed = result['events_processed']
            event_counts = result['event_counts']
            processing_time = result['processing_time']
            
            logger.info(f"Streaming processing completed: {events_processed} events in {processing_time:.2f}s ({result['average_events_per_second']:.1f} events/sec)")
            
        else:
            processing_method = "batch"
            logger.info(f"Processing dataset with optimized batch mode (batch_size={batch_size})")
            events = parse_sysmon_events(log_file_path)
            logger.info(f"Loaded {len(events)} events into memory")
            
            import time
            start_time = time.time()
            process_events_to_graph_optimized(events, neo4j_handler, batch_size, submission_id)
            processing_time = time.time() - start_time
            
            events_processed = len(events)
            
            # Count different event types for summary
            event_counts = {}
            for event in events:
                event_id = event.get('Event', {}).get('System', {}).get('EventID')
                event_counts[event_id] = event_counts.get(event_id, 0) + 1
            
            logger.info(f"Batch processing completed: {events_processed} events in {processing_time:.2f}s ({events_processed/processing_time:.1f} events/sec)")
        
        logger.info("Graph structure created successfully")
        
        result = {
            "message": "File processed and graph created successfully",
            "submission_id": submission_id,
            "events_processed": events_processed,
            "event_counts": event_counts,
            "processing_method": processing_method,
            "processing_time_seconds": processing_time,
            "events_per_second": events_processed / processing_time if processing_time > 0 else 0
        }
        
        return result
            
    except Exception as e:
        logger.error(f"Processing failed: {str(e)}")
        raise e
    finally:
        # Clean up Neo4j connection
        if neo4j_handler:
            neo4j_handler.close()


def main():
    """Main function for command line execution"""
    parser = argparse.ArgumentParser(description='Load Sysmon log data into Neo4j graph database')
    parser.add_argument('log_file', help='Path to the log file containing Sysmon events (JSON format, one event per line)')
    parser.add_argument('--neo4j-uri', default=os.environ.get('NEO4J_URI'), help='Neo4j connection URI (default: from NEO4J_URI env var)')
    parser.add_argument('--neo4j-username', default=os.environ.get('NEO4J_USERNAME'), help='Neo4j username (default: from NEO4J_USERNAME env var)')
    parser.add_argument('--neo4j-password', default=os.environ.get('NEO4J_PASSWORD'), help='Neo4j password (default: from NEO4J_PASSWORD env var)')
    parser.add_argument('--batch-size', type=int, default=DEFAULT_BATCH_SIZE, help=f'Batch size for processing (default: {DEFAULT_BATCH_SIZE})')
    parser.add_argument('--stream-chunk-size', type=int, default=DEFAULT_STREAM_CHUNK_SIZE, help=f'Stream chunk size for large files (default: {DEFAULT_STREAM_CHUNK_SIZE})')
    parser.add_argument('--memory-mode', choices=['auto', 'always', 'never'], default='auto', help='Memory efficient mode (default: auto)')
    
    args = parser.parse_args()
    
    # Generate a unique submission ID
    submission_id = str(uuid.uuid4())
    logger.info(f"Generated submission ID: {submission_id}")
    
    # Override environment variables if provided via command line
    if args.neo4j_uri:
        os.environ['NEO4J_URI'] = args.neo4j_uri
    if args.neo4j_username:
        os.environ['NEO4J_USERNAME'] = args.neo4j_username
    if args.neo4j_password:
        os.environ['NEO4J_PASSWORD'] = args.neo4j_password
    
    try:
        result = process_data(
            args.log_file, 
            submission_id,
            batch_size=args.batch_size,
            stream_chunk_size=args.stream_chunk_size,
            memory_mode=args.memory_mode
        )
        print(json.dumps(result, indent=2))
        logger.info("Processing completed successfully")
    except Exception as e:
        logger.error(f"Processing failed: {str(e)}")
        exit(1)


if __name__ == "__main__":
    main()