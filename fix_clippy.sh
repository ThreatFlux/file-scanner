#\!/bin/bash

# Fix or_insert_with to or_default
find src tests -name "*.rs" -type f -exec sed -i 's/\.or_insert_with(Vec::new)/\.or_default()/g' {} +
find src tests -name "*.rs" -type f -exec sed -i 's/\.or_insert_with(HashMap::new)/\.or_default()/g' {} +
find src tests -name "*.rs" -type f -exec sed -i 's/\.or_insert_with(HashSet::new)/\.or_default()/g' {} +
find src tests -name "*.rs" -type f -exec sed -i 's/\.or_insert_with(BTreeMap::new)/\.or_default()/g' {} +
find src tests -name "*.rs" -type f -exec sed -i 's/\.or_insert_with(BTreeSet::new)/\.or_default()/g' {} +

# Fix unnecessary cast
sed -i 's/mach_o.entry as u64/mach_o.entry/g' src/binary_parser.rs

# Fix needless borrow
sed -i 's/detect_entry_points(&symbols)/detect_entry_points(symbols)/g' src/call_graph.rs

# Fix iter_kv_map
sed -i 's/self.nodes.into_iter().map( < /dev/null | (_, node)| node).collect()/self.nodes.into_values().collect()/g' src/call_graph.rs

# Fix clamp pattern
sed -i 's/((mi \* 100.0 \/ 171.0).max(0.0)).min(100.0)/(mi * 100.0 \/ 171.0).clamp(0.0, 100.0)/g' src/code_metrics.rs

echo "Clippy fixes applied"
