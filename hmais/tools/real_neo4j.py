
from typing import List, Dict, Any, Tuple
from neo4j import GraphDatabase, Driver
import config

class RealNeo4jDB:

    def __init__(self):
        self.driver: Driver = GraphDatabase.driver(
            config.NEO4J_URI,
            auth=(config.NEO4J_USER, config.NEO4J_PASSWORD)
        )
        self._test_connection()

    def _test_connection(self):
        try:
            with self.driver.session(database=config.NEO4J_DATABASE) as session:
                result = session.run("MATCH (n) RETURN count(n) as count")
                count = result.single()["count"]
                print(f"✓ Connected")
        except Exception as e:
            print(f"⚠️  Connection failed: {e}")

    def close(self):
        if self.driver:
            self.driver.close()

    def execute_count_query(self, query: str) -> int:
        try:
            with self.driver.session(database=config.NEO4J_DATABASE) as session:
                result = session.run(query)
                record = result.single()
                if record:

                    return list(record.values())[0]
                return 0
        except Exception as e:
            print(f"Error executing count query: {e}")
            print(f"Query: {query}")
            raise

    def execute_fetch_query(self, query: str) -> List[Dict[str, Any]]:
        try:
            with self.driver.session(database=config.NEO4J_DATABASE) as session:
                result = session.run(query)
                records = []
                for record in result:

                    record_dict = {}
                    for key in record.keys():
                        value = record[key]

                        if hasattr(value, '__dict__') and hasattr(value, '_properties'):
                            record_dict[key] = dict(value._properties)

                            if hasattr(value, 'id'):
                                record_dict[key]['_neo4j_id'] = value.id
                        else:
                            record_dict[key] = value
                    records.append(record_dict)
                return records
        except Exception as e:
            print(f"Error executing fetch query: {e}")
            print(f"Query: {query}")
            raise

    def validate_cypher(self, query: str) -> Tuple[bool, str]:
        try:

            query_upper = query.upper()
            if "MATCH" not in query_upper:
                return False, "Query must contain MATCH clause"
            if "RETURN" not in query_upper:
                return False, "Query must contain RETURN clause"

            test_query = query.replace("RETURN", "RETURN") + " LIMIT 0"
            with self.driver.session(database=config.NEO4J_DATABASE) as session:
                session.run(test_query)
            return True, ""
        except Exception as e:
            return False, str(e)

    def get_database_schema(self) -> Dict[str, Any]:
        try:
            with self.driver.session(database=config.NEO4J_DATABASE) as session:

                labels_result = session.run("CALL db.labels()")
                labels = [record[0] for record in labels_result]

                rel_types_result = session.run("CALL db.relationshipTypes()")
                rel_types = [record[0] for record in rel_types_result]

                node_types_result = session.run(
                    "MATCH (n) RETURN DISTINCT n.type as type LIMIT 20"
                )
                node_types = [record["type"] for record in node_types_result if record["type"]]

                return {
                    "labels": labels,
                    "relationship_types": rel_types,
                    "node_types": node_types
                }
        except Exception as e:
            print(f"Error getting database schema: {e}")
            return {
                "labels": [],
                "relationship_types": [],
                "node_types": []
            }

    def get_sample_data(self, limit: int = 5) -> Dict[str, Any]:
        try:
            with self.driver.session(database=config.NEO4J_DATABASE) as session:

                nodes_result = session.run(f"MATCH (n) RETURN n LIMIT {limit}")
                nodes = []
                for record in nodes_result:
                    node = record["n"]
                    nodes.append({
                        "id": node.get("id"),
                        "type": node.get("type"),
                        "properties": dict(node)
                    })

                rels_result = session.run(
                    f"MATCH (a)-[r]->(b) RETURN a.id as start, type(r) as rel_type, "
                    f"b.id as end, r.start_node_name as start_name, "
                    f"r.end_node_name as end_name LIMIT {limit}"
                )
                relationships = []
                for record in rels_result:
                    relationships.append({
                        "start": record["start"],
                        "end": record["end"],
                        "type": record["rel_type"],
                        "start_name": record["start_name"],
                        "end_name": record["end_name"]
                    })

                return {
                    "sample_nodes": nodes,
                    "sample_relationships": relationships
                }
        except Exception as e:
            print(f"Error getting sample data: {e}")
            return {
                "sample_nodes": [],
                "sample_relationships": []
            }
