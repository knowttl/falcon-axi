# identity graphql

identity graphql          run one read-only Identity Protection GraphQL query

```text
npx -y @knowttl/falcon-axi identity graphql --query <text|@file> [--variables <json>]

--query      GraphQL document text, or @path to a UTF-8 file of at most 1 MiB
--variables  JSON object sent as GraphQL variables; omit for {}

Sends one read-only query to Identity Protection.
The document is parsed and refused unless it contains exactly one operation and that operation is a query.
A document with more than one operation is refused and is not sent.
A mutation, a subscription, or a document that does not parse is not sent.
Variables are a separate JSON object and are never inserted into the document.
Requires Identity Protection GraphQL:write, which Falcon labels write even for reads.
The selected fields may also need Entities:read, Timeline:read, Assessment:read, or Detections:read.
Examples:
  npx -y @knowttl/falcon-axi identity graphql --query 'query { securityAssessment { overallScore } }'
  npx -y @knowttl/falcon-axi identity graphql --query @query.graphql --variables '{"domain":"synthetic.example"}'
```
