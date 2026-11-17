# identity graphql

identity graphql          run one read-only Identity Protection GraphQL query

```text
npx -y @knowttl/falcon-axi identity graphql --query <text|@file> [--variables <json>] [--limit N] [--cursor <token>] [--all] [--max-rows N]

--query      GraphQL document text, or @path to a UTF-8 file
--variables  JSON object sent as GraphQL variables; omit for {}
--limit      rows in this call (default 20, ceiling 200)
--cursor     opaque continuation token from a previous call
--all        walk pages; page size is independent of --limit
--max-rows   row budget (default 1000; requires --all)

Sends one read-only query to Identity Protection.
The document is parsed and refused unless it contains exactly one operation and that operation is a query.
A document with more than one operation is refused and is not sent.
A mutation, a subscription, or a document that does not parse is not sent.
Variables are a separate JSON object and are never inserted into the document.
--limit, --cursor, and --all require exactly one top-level connection whose first and after arguments are variables and whose pageInfo selects hasNextPage and endCursor.
The page size follows identity list: default 20 and ceiling 200.
--all follows detection list: each page uses the 200 ceiling or the remaining --max-rows budget, not --limit.
Requires Identity Protection GraphQL:write, which Falcon labels write even for reads.
The selected fields may also need Entities:read, Timeline:read, Assessment:read, or Detections:read.
Incidents, riskFactors, riskByMembershipSummary, securityAssessmentGoals and securityAssessmentHistory have no fixed command; read them here with a query you write, using --limit, --cursor and --all where the connection is pageable.
This tool ships no fixed document for them and this repo does not verify their field shapes, so discover fields first with a schema query through this command.
Examples:
  npx -y @knowttl/falcon-axi identity graphql --query 'query { securityAssessment { overallScore } }'
  npx -y @knowttl/falcon-axi identity graphql --query 'query { __schema { queryType { name fields { name } } } }'
  npx -y @knowttl/falcon-axi identity graphql --query @query.graphql --variables '{"domain":"synthetic.example"}'
```
