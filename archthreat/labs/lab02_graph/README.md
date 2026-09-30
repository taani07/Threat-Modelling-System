# Lab 02: Trust boundaries and reachability

## Goal

Implement in `starter.py`:

- `crosses_boundary(model, flow)`: the flow's source and target are in different boundaries.
- `is_internet_facing(model, component_id)`: some inbound flow that is **not** a pull flow starts
  in an untrusted boundary. (The component accepts connections from untrusted parties.)
- `receives_untrusted_data(model, component_id)`: some inbound flow, pushed or pulled, starts in
  an untrusted boundary.
- `reachable_from_untrusted(model)`: every component that data from an untrusted zone can reach
  by following flows, transitively. Use breadth-first search with `collections.deque`. Do not
  include the untrusted components themselves.

## Why it matters

These four questions drive most rules. The last one is how ArchThreat finds **indirect prompt
injection**: in `samples/rag-assistant.yaml` the LLM orchestrator never talks to the internet,
yet public web pages reach it through ingest job -> vector store -> orchestrator. BFS finds that
path; a reviewer skimming the diagram often doesn't.

The pull/push distinction came from a real false positive while building this project: a job
that downloads web pages was flagged as "can be overwhelmed by untrusted callers", but nobody
can call it. Data direction and connection direction are different things.

## Python you will learn

- `collections.deque` with `append` / `popleft` (O(1) queue; a list's `pop(0)` is O(n)).
- `any(condition for x in xs)`: short-circuiting generator expression.
- Set difference: `seen - start`.

## Interview questions

- *"How do you find all the places untrusted data can reach?"* Model the data flows as a graph
  and do a reachability search from untrusted sources (taint analysis at the architecture level).
- *"Why is RAG over public content a security concern?"* Anything that ingests attacker-influenced
  content turns into an indirect prompt injection path to the model.
