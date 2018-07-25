import sys
queries = sys.stdin.read().split('\n')
queries = filter(lambda x: len(x) > 0, queries)

print("static inline void db_prepare_all() {");
for q in queries:
    print("    sqlite3_prepare_v2(db, sql_%s, -1, &stmt_%s, NULL);" % (q, q))
print("}");

print("static inline void db_finalize_all() {");
for q in queries:
    print("    sqlite3_finalize(stmt_%s);" % (q));
print("}");
