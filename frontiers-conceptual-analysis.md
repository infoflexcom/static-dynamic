# Static-Dynamic Hybrid Verification of Context-Dependent Security Vulnerabilities in LLM-Synthesized Python and JavaScript Microservices: A Conceptual Analysis

## Abstract

Security weaknesses in microservices cannot always be judged from source code alone. Whether a request is authorized, for example, may depend on the identity of the caller, the owner of a record, the network route, and the checks performed by other services. This problem also affects services produced with large language models (LLMs). This article develops the argument that hybrid security verification should treat the combination of a policy, an execution context, and an evidence trail as its basic unit of analysis, rather than treating a static warning or a successful test as a complete security judgment. It proposes a context-indexed security obligation and a three-state evidence model: observed violation, contradicted candidate within a stated test scope, and unresolved. A worked authorization example shows why the same backend code can produce different security judgments under different deployments, and why a denied request does not by itself prove that the backend enforces access control. The article relates the model to research on generated-code security, microservice trust, and hybrid vulnerability detection. It identifies conditions under which the proposed model can support a bounded conclusion, as well as limits caused by incomplete policies, uncertain traces, and untested contexts. The contribution is a conceptual model and an agenda for empirical evaluation; no implementation, dataset, or performance result is claimed.

**Keywords:** large language models, microservices, static analysis, dynamic analysis, security policy, access control, Python, JavaScript.

## 1. Introduction

Large language models (LLMs) can generate application code from a written request. They can produce API handlers, database operations, and service configuration in languages such as Python and JavaScript. A generated program may work correctly for an ordinary request while failing to enforce a security rule. Pearce et al. (2022) found insecure suggestions in selected security-sensitive code-generation scenarios. Perry et al. (2023) observed that participants using an AI assistant wrote less secure code in their study and were more likely to believe their code was secure. These findings concern particular tools and tasks; they do not establish a universal rate of insecure AI-generated code.

A later study of code found in public GitHub projects examined Python and JavaScript snippets associated with several code-generation tools and reported a range of security weaknesses (Fu et al., 2025). Such research gives a reason to examine generated code, but a snippet alone is not the deployed application. A generated endpoint may be placed behind a trusted gateway, called directly from the internet, or used only by another service. Each arrangement changes which security conditions matter.

Authentication and authorization in microservices depend on relationships between services as well as on local checks (de Almeida and Canedo, 2022). For example, the correct behavior of an order endpoint depends on who makes the request, who owns the order, and whether the user is permitted to act as an administrator. A static warning about a route is therefore not equivalent to proof that an unauthorized user can reach and misuse it. Conversely, a dynamic test that receives a denial does not show that every relevant route and deployment is secure.

Hybrid approaches combine static and dynamic analysis to address some of their separate limitations. Static analysis examines code without running the application, while dynamic analysis observes selected executions. Nunes et al. (2025) already proposed and studied a hybrid approach for web application vulnerability detection. The contribution of this article is not the invention of hybrid testing. Instead, it develops an explicit way to connect a security policy, microservice deployment context, and test evidence to the conclusion a reviewer may draw. Its central claim is:

> A security conclusion about a context-dependent microservice weakness must be indexed to a stated policy and deployment context, and its strength must not exceed the evidence collected in that context.

The analysis develops this claim in four steps. First, it separates code properties from system-level policy violations. Second, it defines a context-indexed security obligation. Third, it gives rules for combining static and dynamic evidence without treating non-observation as proof of absence. Fourth, it demonstrates the model with hypothetical access-control cases and identifies testable implications. The examples are thought experiments, not experimental results. The focus on LLM-synthesized code reflects the need to verify generated artifacts, not a claim that the proposed security principles apply only to LLM output.

## 2. Background and Position in Existing Work

### 2.1 Generated code and security

A code assistant may generate an insecure implementation even when the output looks plausible. Pearce et al. (2022) investigated completions in weakness-related scenarios, while Fu et al. (2025) examined generated code found in projects. Perry et al. (2023) studied developers interacting with an assistant. These studies address related but different questions: generated suggestions, code found in projects, and human use of an assistant. Their results cannot be combined into one estimate of risk for a complete microservice system.

The present analysis is concerned with the verification of the resulting system. It does not require an LLM to perform the security analysis. An LLM could help suggest code, tests, or rules, but those suggestions would be untrusted inputs to a review process. This distinction is important because a tool's ability to generate code is not evidence that its security judgments are correct.

### 2.2 Context and microservice trust

A review of authentication and authorization in microservices identifies service communication, service trust, and access control as significant concerns (de Almeida and Canedo, 2022). A gateway can authenticate a client, but the security of a downstream service depends on how it receives identity information, whether the gateway protects every relevant route, and whether another path bypasses the gateway. Trust is therefore an architectural condition, not merely a property of a function name or HTTP header.

For this article, **context** means the information needed to interpret a security obligation: the caller and its authority, the operation and resource, the relevant data state, the route to the service, and the assumed trust and deployment configuration. A context is not a replacement for a security policy. The policy states what is permitted; the context states the circumstances in which that rule is assessed.

### 2.3 Static, dynamic, and hybrid analysis

Static analysis can identify potential paths from untrusted input to sensitive operations and can search for missing checks. Its coverage is limited by its models of frameworks, language features, libraries, and configuration. It may report a path that cannot occur in the deployment under review. Dynamic testing can show what happens for a particular input and environment, but a test that does not observe a violation cannot rule out a violation on another path or under another configuration.

DART illustrates how execution information can guide automated tests toward alternative paths (Godefroid et al., 2005). Nunes et al. (2025) combine static and dynamic techniques for web vulnerability detection and present a case study. These works establish that combining analysis techniques is not new. The specific emphasis here is on the meaning of the resulting security judgment: a candidate, a policy, a context, a route, and observed evidence must be linked before a conclusion is assigned.

IRIS combines LLMs and static analysis to infer taint specifications and help assess alerts in repositories (Li et al., 2025). It addresses the problem of improving static analysis with LLM assistance. The present model instead treats the code under examination as potentially LLM-synthesized and specifies how static candidates and runtime observations should be interpreted against a policy and deployment context. The two approaches could be complementary; no comparative performance claim follows from this conceptual distinction.

### 2.4 Scope of the conceptual contribution

The article focuses on HTTP-based Python and JavaScript microservices, especially object-level authorization and identity propagation. Injection and service-to-service trust are used as secondary examples. The context-indexed model is intended to be reusable across languages, but this article does not establish its coverage for asynchronous messaging, distributed transactions, race conditions, or all forms of vulnerability.

The literature cited here is selected to explain and challenge the argument. It is not presented as a systematic review or as an exhaustive search of the field. The proposed combination of concepts is a conceptual contribution whose practical novelty and value remain open to peer review and empirical study.

## 3. Why Context Must Be Part of a Security Judgment

### 3.1 Weakness, reachability, and violation are different concepts

A **code-level weakness** is a property that may contribute to an unsafe outcome, such as trusting a request header as an administrator role. A **reachable behavior** is an execution that can occur under stated assumptions. A **policy violation** occurs when a reachable behavior does something the applicable policy forbids. These concepts overlap, but they are not interchangeable.

A missing ownership check inside a backend endpoint can be an important code-level weakness. Whether it causes an externally reachable violation depends on the full deployment and policy. If a verified gateway checks ownership for every request and direct backend access is impossible, the backend code alone does not establish an externally reachable violation in that deployment. The missing check can still matter for defense in depth and can become exploitable after a configuration change. If the backend is directly reachable without the gateway, the same code may violate the same policy.

This distinction prevents two opposite errors. The first is to report every suspicious code pattern as a proven vulnerability. The second is to dismiss a weakness simply because one tested route happens to be protected. The correct conclusion identifies which property has been established and under what assumptions.

### 3.2 An indistinguishability argument

Consider two systems with identical backend source code and the same business rule: a customer may read only their own orders. In the first system, a trusted gateway checks order ownership and the backend accepts requests only from that gateway. In the second, the backend is reachable directly by customers and performs no ownership check. Assume both descriptions accurately state the network and gateway behavior.

A source-only inspection of the identical backend cannot distinguish these two deployments. Yet the system-level policy judgment can differ: the direct route in the second system permits an unauthorized read, while the stated gateway and network assumptions exclude that route in the first. Thus, a procedure that has access only to the backend source cannot always determine the deployment-level authorization judgment. This is a logical observation about the information available, not a claim that static analysis cannot analyze deployment configuration or gateway code when those are supplied.

The reverse also matters. A single runtime denial in the first system does not prove that all gateway routes or backend entry points are protected. Finite tests observe selected executions; a stronger conclusion requires either additional evidence or explicit assumptions about the unobserved cases.

### 3.3 Context as a structured obligation

Let a **security obligation** be expressed as:

**O = (A, P, C, B, V)**

where:

- **A** identifies the application and its version, including the relevant services;
- **P** is an explicit policy, including permitted and forbidden effects;
- **C** is the context: identity, operation, resource, data state, route, and trust assumptions;
- **B** is the relevant boundary or candidate behavior, such as a gateway-to-service call or a database operation;
- **V** identifies the deployment and configuration version under which the obligation is assessed.

For example, an obligation might state: in deployment version V1, a customer A requesting order B through the public gateway must not receive B's order data when B owns the order and A has no delegated authority. It should also specify what counts as disclosure. HTTP status alone may be an inadequate oracle if an error response includes sensitive data.

The obligation is the unit of reasoning, not necessarily a single line of code or a single test request. One code location may participate in many obligations, and one obligation may involve several services. A change in policy, gateway configuration, network exposure, or application version creates a new or revised obligation. The original conclusion remains attached to its recorded context instead of silently carrying over.

## 4. A Context-Indexed Hybrid Verification Model

### 4.1 Components and their roles

The model separates five components:

1. **Policy and context register:** records the security rule, permitted effects, test identities, data state, routes, and trust assumptions.
2. **Static candidate analysis:** identifies possible paths, missing checks, source-to-sink flows, or boundary crossings relevant to an obligation.
3. **Test construction:** selects safe, controlled requests and fixture states that exercise the candidate under a particular context.
4. **Runtime observation and oracle:** records responses and, when possible, relevant traces; the oracle compares observed effects with the independently stated policy.
5. **Evidence assessment:** assigns a bounded outcome and records gaps in coverage, trace reliability, and assumptions.

Static and dynamic components have different responsibilities. A static candidate explains why an obligation deserves investigation and may help select a test. A dynamic observation can establish that a specified action occurred in an execution. The oracle determines whether that action violates the policy. Neither a tool alert nor a successful HTTP response alone is a complete security judgment.

### 4.2 Evidence record

For each obligation, an evidence record should contain at least the candidate identifier; the policy and configuration versions; the caller and resource relationship; the request path; expected and observed effects; relevant trace or coverage evidence; tool and runtime versions; and the limits of the test. When a required value is unknown, the record should say so.

Identity and ownership must be represented as relationships rather than only as raw values. A test that requests order `123` is not meaningful for authorization unless the record states who owns that order, who requested it, and what the requester is permitted to do. Similarly, an identity header is not trustworthy merely because it is named as if it came from a gateway. The deployment must establish who can set or alter it.

An evidence record should be reproducible without exposing real credentials or personal data. Synthetic users, test secrets, and isolated data are preferable. Trace collection itself is an assumption: missing instrumentation, sampling, or incorrect correlation across services can make an apparent execution path unreliable.

### 4.3 Three outcome states

The following states describe the evidence for a **particular obligation and candidate**:

| Outcome | Minimum condition | Meaning and limit |
|---|---|---|
| **Observed violation** | A reproducible execution in the stated context produces an effect forbidden by the independently specified policy. | The policy was violated in that execution and configuration. It does not show how often the violation occurs or that every deployment is affected. |
| **Contradicted within tested scope** | The tested execution satisfies the candidate's relevant preconditions, reaches the relevant behavior or enforcement point, and does not produce the predicted forbidden effect. | The candidate's predicted outcome did not occur for those recorded cases. Other inputs, routes, and configurations remain open. |
| **Unresolved** | Policy, context, reachability, observation, or the result is missing, inconsistent, or insufficient to meet either condition above. | No determination is justified for the obligation. |

A denied request is not enough to contradict a candidate if it was blocked before the component under investigation was reached. For example, gateway denial does not establish that direct backend access would be denied. A test may legitimately contradict the narrower claim that a particular gateway request results in disclosure, but it cannot resolve a distinct claim about an untested backend route.

The categories describe evidence, not permanent properties of the software. A later test may confirm a violation for another context or invalidate an earlier assumption. If results conflict within the same supposedly identical context, the case should be unresolved until the configuration, data state, and trace discrepancy are explained.

### 4.4 Decision procedure and conditional guarantees

For each obligation, the reviewer or a future tool should:

1. Freeze the application, policy, and deployment configuration; identify unknown context.
2. Generate or collect a static candidate and state its predicted forbidden effect and required preconditions.
3. Choose a controlled test that satisfies those preconditions and an oracle that is independent of the tool's warning.
4. Run the test, record the resulting effect, and establish whether the relevant boundary or enforcement point was reached.
5. Apply the three outcome rules and preserve the scope and assumptions with the result.

Under the assumptions that the context record is accurate, the oracle correctly represents the policy, and the observation is faithful and reproducible, an observed violation supports the conclusion that **at least one** execution violates the policy in that configuration. If any of these assumptions is false, the conclusion can also be false. Conversely, even if a contradicted result is accurate, it establishes only the absence of the predicted effect in the exercised cases; it is not a universal proof. A general proof would require a sound and complete argument over all relevant states and paths, which the proposed finite testing procedure does not provide.

A test that cannot be generated or executed remains unresolved. This rule is essential because difficult-to-reach paths and missing policies are common reasons for a test to fail. Recording unresolved cases exposes uncertainty rather than turning it into a false security guarantee.

### 4.5 How the components relate

The model is deliberately asymmetric. Static analysis can produce candidates without executing a service, but an alert does not prove that a policy was violated. Dynamic testing can reveal a violation without a prior static alert, but its result applies to its observed context. A dynamic-only discovery should therefore be entered as an obligation and evidence record even when no static candidate exists; otherwise a static stage could hide weaknesses it fails to recognize.

This feature distinguishes the conceptual model from a strictly sequential pipeline in which every finding must begin with a static warning. Hybrid verification may use static results to guide tests while retaining independent dynamic tests for coverage. Whether such a design improves detection or increases cost is an empirical question.

## 5. Worked Thought Experiment: Cross-User Order Access

### 5.1 Policy and system

Assume an LLM produces a Python order service with `GET /orders/{id}`. A JavaScript gateway authenticates users and forwards requests. The business policy is: a customer may read an order only if the customer owns it; an administrator may read any order. The test data contain customer A, customer B, and an order owned by B. Assume A is not an administrator and has no delegated access.

A static analyzer finds that the backend uses the requested order identifier to obtain an order and return its details. It finds no modeled ownership check in that backend route. This is a candidate code-level weakness. It is not yet proof that a public user can receive another person's order: that requires information about the gateway, network paths, policy, and data.

### 5.2 Three contexts and conclusions

| Context | Hypothetical observation | Appropriate assessment |
|---|---|---|
| **C1: Public gateway path.** The gateway checks ownership before forwarding. | A's request for B's order is denied at the gateway; no backend trace exists. | The request did not cause disclosure in C1. The backend candidate remains unresolved because its relevant path was not reached. |
| **C2: Direct backend path.** Network configuration allows A to reach the backend. | A's request reaches the backend and returns B's order data. The result is reproducible. | Observed violation of the stated policy in C2, assuming identity, ownership, observation, and configuration records are correct. |
| **C3: Direct backend path after a repair.** The backend checks ownership. | The request reaches the backend authorization check and is denied without disclosing B's data. | The predicted disclosure is contradicted for this test in C3; other users, routes, and operations remain untested. |

The source may be identical in C1 and C2, but the reachable behavior differs because the network path differs. In C3 the code has changed, so its evidence must not be silently applied to C2. If the policy intended the backend to enforce ownership independently of the gateway, the missing backend check would itself violate that separate architectural policy even in C1. This illustrates why the policy must identify the required property before the evidence is interpreted.

### 5.3 Boundary identity and injection

Consider a second hypothetical candidate: a JavaScript service treats a client-supplied role header as proof of administrator status. The policy says that only an authenticated administrator may call an administrative operation. A runtime test using a non-administrator and a controlled header can establish a violation if the forbidden operation occurs. If a gateway strips and replaces external headers, the conclusion depends on the tested route and the trustworthiness of that replacement; a direct backend route must be assessed separately.

For injection, the same distinction between action and oracle applies. A suspicious input reaching a query API is a candidate. A database error alone does not prove that input changed query structure. A controlled test needs evidence that the data were interpreted as unintended query structure or that another policy-forbidden effect occurred. The exact oracle depends on the database and intended operation. The authorization and injection examples show that **context and oracle design differ by weakness**, even when a common evidence structure is used.

## 6. Implications and a Research Agenda

### 6.1 Falsifiable propositions

The model yields propositions that can be evaluated, but none is treated here as an established finding:

- **P1 — Context discrimination:** When the same code is evaluated under deployments with different trust boundaries, context-indexed obligations can distinguish deployment-specific security conclusions that a source-only assessment cannot distinguish without additional deployment information.
- **P2 — Evidence quality:** Requiring an explicit policy oracle and route evidence will reduce the number of reports incorrectly described as confirmed violations, compared with classifying every static alert as confirmed, provided both methods use the same independently labeled cases.
- **P3 — Cost and coverage trade-off:** Using static candidates to guide runtime tests may exercise more relevant obligations within a fixed test budget than unguided tests, but the result depends on candidate quality and may be worse when static analysis misses paths.
- **P4 — Uncertainty visibility:** An explicit unresolved state will expose cases that binary reporting hides; whether it improves a reviewer's decisions requires user or operational evaluation.

P1 follows from the indistinguishability argument only for cases in which the relevant deployment information is absent from the source-only input. P2–P4 are empirical hypotheses. None implies that hybrid analysis is always more accurate or efficient.

### 6.2 Proposed evaluation

A future evaluation could generate or collect Python and JavaScript applications with recorded prompts, model versions, human edits, service configuration, and explicit policies. The study should include independently labeled obligations with both vulnerable and non-vulnerable cases, including paired changes to ownership, gateway routing, and backend reachability. Seeded weaknesses and naturally occurring weaknesses should be reported separately.

At least two reviewers should independently label each obligation using source, configuration, policy, and controlled evidence, with disagreements adjudicated. They should inspect obligations beyond tool alerts to allow false negatives to be counted. Labels that remain uncertain should be reported separately. The evaluation should split by application and prompt family to reduce overlap between rule development and final evaluation.

Comparable conditions should include static-only reporting, dynamic-only testing, and the hybrid model. All conditions need the same frozen policies and test environments. A dynamic-only baseline must not receive static paths, while hybrid testing may use them; test budgets and setup costs should be stated. An additional ablation could remove the context register or replace guided tests with unguided tests. Since a missing context may prevent a meaningful policy oracle, such an ablation should report unresolved or inapplicable cases rather than inventing missing facts.

The principal unit should be an obligation rather than a raw alert. For a confirmation task, observed violations count as positive; contradicted and unresolved cases count as not confirmed. Report the unresolved rate separately so that an unresolved case is not described as safe. Compare precision, recall, and false-positive rate against the independent labels; report counts, time, test requests, and context coverage. Use application-level clustered uncertainty intervals because obligations from the same application may be related. Methods should have equal and explicitly stated test budgets, and operational failures and timeouts should be reported. This is a proposed design, not a claim that any study has been performed.

### 6.3 Practical implications

A team applying the model would begin by documenting a small set of high-value rules, such as who may read an order and which services may set identity headers. It could then connect existing static findings and controlled tests to those rules. The model does not require a new analyzer, but it does require policy and deployment information that may not be readily available. Its cost may be substantial where services, environments, or permissions change frequently.

Reports should preserve unknowns, differentiate risk from observed impact, and avoid logging real customer records or credentials. Test environments should be isolated, with synthetic data and restricted outbound network access. Discovered weaknesses in real systems should be handled through responsible disclosure.

## 7. Discussion

The key conceptual advance is a change in the object of verification. Instead of asking only whether a code location looks unsafe, the model asks whether a specified operation satisfies a policy in a specified system context, and what evidence supports the answer. This makes the connection between policy, code, configuration, and behavior explicit. It also makes the limits of a negative test visible.

The model does not eliminate false positives or false negatives. A faulty policy oracle can label permitted behavior as a violation. A stale deployment description can hide a direct route. An incorrect trace can create a false impression that an enforcement point was reached. A narrow test budget can miss real attacks. Frameworks that rely on dynamic language features, message queues, external identity providers, or shared mutable state may require additional modeling. A gateway that appears to enforce access control can also have its own bugs, which require separate obligations and evidence.

The model is not uniquely dependent on LLMs: human-written microservices face the same contextual problem. LLM synthesis matters because code and configuration may be produced rapidly and because generated fragments can be accepted without full understanding of surrounding assumptions. Provenance should be recorded in future studies, but it does not change the logic of whether a policy is violated.

The term **verification** is used here for bounded, evidence-based checking, not a formal proof that a service is secure. The framework is conceptual and has not been implemented or benchmarked in this article. Its main practical claims remain hypotheses, and its distinction from existing hybrid systems should be assessed against further literature and implementation work.

## 8. Conclusion

A context-dependent security judgment requires more than a suspicious source-code pattern or one runtime response. This article proposed the context-indexed security obligation as a way to connect application version, policy, caller, resource, trust boundary, and deployment. It also defined three evidence states that distinguish an observed violation from a candidate contradicted in a limited scope and a case that remains unresolved.

The worked example shows why identical backend code can support different deployment-level conclusions and why a gateway denial does not automatically establish backend protection. The model offers a structured basis for testing LLM-synthesized microservices, but its usability, detection performance, and cost remain to be tested. Future work should implement the model, construct independently labeled obligations, and evaluate it against static-only and dynamic-only baselines without treating a passing test as proof of universal security.

## References

de Almeida, M. G., and Canedo, E. D. (2022). Authentication and authorization in microservices architecture: A systematic literature review. *Applied Sciences* 12:3023. doi: 10.3390/app12063023.

Fu, Y., Liang, P., Tahir, A., Li, Z., Shahin, M., Yu, J., et al. (2025). Security weaknesses of Copilot-generated code in GitHub projects: An empirical study. *ACM Transactions on Software Engineering and Methodology* 34, Article 218, 1–34. doi: 10.1145/3716848.

Godefroid, P., Klarlund, N., and Sen, K. (2005). “DART: Directed automated random testing,” in *Proceedings of the 2005 ACM SIGPLAN Conference on Programming Language Design and Implementation* (New York, NY: ACM), 213–223. doi: 10.1145/1065010.1065036.

Li, Z., Dutta, S., and Naik, M. (2025). “IRIS: LLM-assisted static analysis for detecting security vulnerabilities,” in *International Conference on Learning Representations*. Available at: https://par.nsf.gov/biblio/10617377.

Nunes, P., Fonseca, J., and Vieira, M. (2025). Blending static and dynamic analysis for web application vulnerability detection: Methodology and case study. *IEEE Access* 13, 3139–3153. doi: 10.1109/ACCESS.2024.3522094.

Pearce, H., Ahmad, B., Tan, B., Dolan-Gavitt, B., and Karri, R. (2022). “Asleep at the keyboard? Assessing the security of GitHub Copilot's code contributions,” in *2022 IEEE Symposium on Security and Privacy* (IEEE), 754–768. doi: 10.1109/SP46214.2022.9833571.

Perry, N., Srivastava, M., Kumar, D., and Boneh, D. (2023). “Do users write more insecure code with AI assistants?,” in *Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security* (New York, NY: ACM). doi: 10.1145/3576915.3623157.
