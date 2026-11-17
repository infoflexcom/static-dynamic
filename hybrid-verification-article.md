# Static-Dynamic Hybrid Verification of Context-Dependent Security Vulnerabilities in LLM-Synthesized Python and JavaScript Microservices

**Article type:** Conceptual research article and proposed empirical study

## Abstract

Large language models (LLMs) can generate microservice code quickly, but functional code is not always secure. Some vulnerabilities depend on context, such as the identity of the caller, the ownership of a resource, network access, or the way services communicate. These conditions are difficult to assess by reading a single code fragment. Static analysis can examine code without running it, while dynamic analysis can observe behavior during execution. However, static analysis may report infeasible paths, and dynamic analysis may miss paths that its tests do not exercise. This article proposes a hybrid verification framework for LLM-synthesized Python and JavaScript microservices. The framework combines static source-to-sink analysis, explicit security policies, deployment context, and controlled runtime tests. It records findings as confirmed violations, unresolved candidates, or candidates contradicted within a defined test scope. A proposed evaluation compares the hybrid approach with static-only and dynamic-only baselines using a labeled dataset of generated services and paired secure and insecure configurations. Outcomes would include precision, recall, false-positive rate, runtime cost, and coverage of cross-service security conditions. No implementation or experiment is reported here, and the framework's effectiveness remains to be established. The proposed contribution is a testable approach for connecting code-level warnings with evidence about actual service behavior.

**Keywords—** large language models, microservices, static analysis, dynamic analysis, hybrid verification, Python, JavaScript, access control, software security.

## I. Introduction

Large language models are increasingly used to write application code from natural-language instructions. A developer can ask an LLM to generate an application programming interface (API), a database query, or an authentication function. These capabilities can reduce development effort, but generated code must still be checked for security weaknesses.

Pearce *et al.* examined code suggestions in security-sensitive scenarios and showed that generated code can contain weaknesses [1]. Perry *et al.* found that participants using an AI coding assistant produced less secure code in their study and were more likely to believe that their code was secure [2]. These results are specific to the models, tasks, and settings studied; they do not establish a universal vulnerability rate for current LLM-generated systems.

Microservices add another challenge. A microservice application divides a system into small services that communicate through APIs or messages. Authentication and authorization depend not only on code within each service but also on trust between services and the deployment environment [3]. For example, a service may accept a user identifier in a request and return a record without checking whether the caller owns it. The same endpoint could be protected by a trusted gateway in one deployment and exposed directly in another. Therefore, the security of a code fragment cannot always be determined without its context.

Static application security testing (SAST) examines code without executing it. It can identify suspicious patterns and possible flows from untrusted input to sensitive operations. Dynamic application security testing (DAST) runs an application and observes its responses. Each method has limitations: a static warning may describe a path that is not reachable, while a dynamic test may fail to reach a real weakness. Earlier work has explored the use of static information to guide dynamic vulnerability detection [4] and automated testing [5].

This article proposes a hybrid framework that applies these ideas to context-dependent weaknesses in LLM-synthesized Python and JavaScript microservices. Its intended contribution is the combination of an explicit context model, guided runtime tests, and evidence-based outcome categories. The article also presents a reproducible evaluation plan. It does not claim that the proposed approach has been implemented, validated, or shown to outperform existing tools.

The research questions are:

- **RQ1:** Can a hybrid approach identify context-dependent vulnerabilities more accurately than static-only and dynamic-only approaches under the same evaluation conditions?
- **RQ2:** Which types of context, such as user identity, resource ownership, and service exposure, are needed to explain and test the identified weaknesses?
- **RQ3:** What additional execution time and testing effort does the hybrid approach require?

## II. Background and Related Work

### A. Security of LLM-generated code

Code generation studies show that a plausible completion may still have an insecure implementation. Pearce *et al.* tested generated code against selected weakness scenarios [1]. A study of Copilot-generated code in public GitHub projects also reported diverse security weaknesses, although identifying generated code in real projects is itself difficult [6]. Such studies motivate verification, but snippet-level findings do not automatically describe risks in a complete deployment.

LLM-assisted development also involves human decisions. In the user study by Perry *et al.*, the participants' results depended on their interaction with an assistant and on the tasks they performed [2]. Thus, generated code should be examined together with its requirements and surrounding system, rather than trusted solely because it executes successfully.

### B. Microservice security and context

Microservices communicate across process and network boundaries. A request can pass through a gateway, an identity service, a business service, and a database. Security depends on how identity and permissions are checked at these boundaries. A review by de Almeida and Canedo highlights challenges involving service-to-service communication, trust, and access control [3].

In this article, a **context-dependent vulnerability** is a security weakness whose existence or practical impact depends on a stated combination of code, configuration, user authority, data state, or deployment conditions. Context is not limited to the source code. It includes the assumptions that make a security rule meaningful, such as which user owns a record and whether a backend endpoint is reachable without the gateway.

### C. Static and dynamic analysis

A static analyzer may model a flow from a source, such as an HTTP parameter, to a sink, such as a database query or operating-system command. It can also inspect whether a security check appears along the path. Because runtime values and deployment behavior may be unknown, a candidate path is not necessarily an actual violation.

Dynamic analysis executes the system with selected inputs and checks observable results. It can establish that a particular request violates a specified policy in a particular environment, but its conclusions are limited to the tested cases. Hybrid methods can use a static candidate to focus dynamic testing. Prior work used static taint information to guide tests for buffer overflows in C [4]; DART combined execution information and input generation to explore program paths [5]. Neither result by itself establishes effectiveness for the microservice setting proposed here.

## III. Problem Definition and Scope

Consider a system consisting of one or more Python or JavaScript services, their configuration, and a stated security policy. Let a test context be represented as:

**C = (I, R, D, N, S)**

where **I** is the caller's identity and role, **R** is the requested operation and resource, **D** is the relevant data state and ownership, **N** is the network and gateway configuration, and **S** describes service-to-service trust and credentials. A security policy specifies permitted behavior for such contexts. For example: “A customer may read only records belonging to that customer; an administrator may read all records.”

The attacker is assumed to control ordinary client requests, including route parameters, headers that an untrusted client can send, and request bodies. For service-to-service cases, the evaluation separately specifies whether the attacker can reach a backend service directly or control a service credential. The attacker is not assumed to control the policy, trusted identity provider, application source code, or database directly. Those assumptions may change between test cases, but must be recorded.

The initial scope covers HTTP-based Python and JavaScript services and four weakness families: object-level authorization, injection, unsafe trust in client-supplied identity, and unsafe inter-service access. It excludes a claim of complete coverage of every framework, asynchronous message protocol, third-party dependency, or production deployment. Results apply only to the tested configuration and stated policy.

## IV. Proposed Hybrid Verification Framework

### A. Inputs and context model

The proposed framework takes source code, dependency and deployment configuration, API descriptions when available, and a machine-readable or manually specified security policy. Test fixtures define users, roles, resource owners, and permitted network routes. Unknown or missing context is recorded explicitly rather than silently assumed to be secure or insecure.

A context record should contain the route, service, caller identity, requested resource, expected authorization decision, deployment entry point, and relevant trust assumptions. Configuration and policy inputs require review because an incorrect policy can produce a convincing but incorrect result.

### B. Static candidate discovery

A static stage parses Python and JavaScript code and identifies routes, input sources, relevant security checks, and sensitive operations. The initial implementation could use existing analyzers such as CodeQL for supported language data-flow queries [7]. Additional rules would be needed for application-specific authorization and for mapping trust across services.

Each candidate should include a service and route, a potential source-to-sink path, the suspected weakness, an associated policy, and the conditions required for a meaningful test. Cross-service flows may be reconstructed from API specifications and configuration, but dynamic route construction and incomplete configuration can make the reconstruction uncertain. Static candidates are **leads**, not proof of exploitation.

### C. Context-guided dynamic testing

The dynamic stage starts services in an isolated environment with synthetic data and test credentials. For each candidate, it creates requests that vary relevant context while keeping unrelated factors as stable as possible. Examples include changing the authenticated user, changing resource ownership, and accessing a backend through an allowed or blocked network route.

Test generation may combine hand-written templates, input mutation, and path-guided techniques where practical. The framework should enforce time, request, and resource limits. Tests involving commands, databases, or network destinations must use controlled fixtures and must not target real user data or external systems.

### D. Evidence fusion and decision rules

The framework combines static evidence, test inputs, expected behavior, observed responses, and, when available, instrumented traces. It reports the following categories:

1. **Confirmed violation:** a reproducible test violates the stated policy in the specified configuration. Evidence includes the request context and the observed effect, not merely an error message.
2. **Contradicted within tested scope:** the specific candidate's stated violation does not occur under the recorded tests and the candidate path or relevant enforcement point was observed. This does not prove the application secure.
3. **Unresolved:** the test cannot reach the path, required context is missing, the oracle is inconclusive, or the result cannot be reproduced.

A confirmed violation requires an independent policy oracle: reaching a sensitive API alone is not sufficient. A blocked request alone is also insufficient to dismiss a candidate if the test never reached the relevant code or did not represent the required context. The report should include software versions, input seeds, configuration, policy, trace identifiers, and limitations. Sensitive values in logs should be redacted.

### E. Workflow

The proposed workflow is: **collect code and context → find static candidates → map each candidate to a policy and test fixture → execute targeted tests in isolation → compare observed behavior with the policy → report evidence and uncertainty**. A security reviewer can use the report to decide whether to fix the code, change the configuration, or investigate further. A suggested fix must be retested; LLM-generated repairs should not be accepted without verification.

## V. Illustrative Scenarios

The following scenarios are hypothetical and explain the proposed method. They are not experimental findings.

### A. Cross-user record access

Suppose a Python order service exposes `GET /orders/{id}`. It verifies that a caller is logged in but looks up an order by its identifier without comparing its owner to the caller. A static rule marks the route because a user-controlled identifier reaches a record lookup and no relevant ownership check is found on the modeled path.

The test fixture creates users A and B and an order owned by B. The policy permits A to read only A's orders. The test authenticates as A and requests B's order. If the response exposes B's order, the policy is violated and the candidate is confirmed for that configuration. If the request is denied and tracing shows that the relevant authorization check was executed, this candidate is contradicted within that test scope. A failed setup or an unreachable route leaves it unresolved.

### B. Trusting a client-supplied identity header

Suppose a JavaScript service reads an `X-User-Role` header and treats the value `admin` as proof of administrator status. A static rule identifies a client-controlled header reaching an authorization decision. The dynamic test uses a non-administrator account and sends the header while requesting an administrator-only operation. If the operation succeeds, the test confirms a violation of the stated role policy.

The network context matters: a trusted gateway might strip external headers and set its own verified value. The evaluation should therefore test both the gateway path and, where the deployment permits it, direct backend access. A result for one path must not be generalized to another.

### C. Injection through a service boundary

Suppose an API forwards a search term to a second service, where it is incorporated into a database query. Static analysis may identify a possible flow across the two services. In a controlled database, the dynamic test supplies a harmless marker designed to distinguish data from query structure, then compares the observed query or result with a predefined oracle. The presence of unusual input or a server error alone does not establish injection. Parameterized query behavior, if observed for the relevant path and cases, can contradict the specific candidate within the tested scope.

## VI. Proposed Empirical Evaluation

### A. Dataset and ground truth

A future study should create a dataset from documented prompts that ask multiple LLMs to generate Python and JavaScript microservices with API, data, and authorization requirements. Record model names and versions, generation dates, prompt text, sampling settings where available, and all human edits. Include both single-service and multi-service applications, and report failed generations rather than silently discarding them.

Construct matched cases by changing one relevant condition at a time, such as resource ownership, gateway reachability, or an authorization check. Include intentionally vulnerable and secure cases as well as naturally occurring generated weaknesses. Clearly separate seeded cases from naturally generated findings when reporting results. Cases should include negative examples that resemble vulnerable patterns but are protected under their specified context.

The unit of analysis is a **candidate security obligation**: one policy, route or operation, context, and weakness category. Two independent security reviewers should label every obligation as vulnerable, non-vulnerable, or uncertain using the policy, code, configuration, and controlled evidence. Reviewers should be blinded to the evaluated method's output where feasible; disagreements should be adjudicated and agreement reported. Uncertain cases should be reported separately and excluded from primary accuracy denominators, with a sensitivity analysis for alternative labels. Review of only tool-reported alerts would miss false negatives and is insufficient for ground truth.

Split cases by application template and prompt family, not by individual request, to reduce leakage between development and evaluation. Keep final test cases hidden while rules and templates are developed. Record sample sizes by language, weakness, model, and context; determine the final size before testing through feasibility and precision or power analysis.

### B. Comparison methods

Evaluate three conditions on the same frozen applications, policies, and test environments:

1. **Static-only:** configured static rules report candidate violations without runtime confirmation.
2. **Dynamic-only:** policy-based tests use the same test harness and total runtime budget but no static candidate paths.
3. **Hybrid:** the proposed static stage guides dynamic tests and applies the evidence-fusion rules.

The static and dynamic tools, versions, rules, test budgets, and configuration must be published. Where possible, include an ablation in which the hybrid method uses unguided tests or omits selected context fields. This helps determine whether improvement is associated with guidance or with context. It should not be assumed in advance that one method is superior.

For a comparable binary primary analysis, count a hybrid **confirmed violation** as positive and all other outcomes as not confirmed. This conservative mapping makes unresolved vulnerable obligations false negatives for the confirmation task; report the unresolved rate and a separate candidate-level analysis so that lack of confirmation is not mistaken for a proof of safety. Match each alert to a labeled obligation by route, weakness, and context, and deduplicate multiple alerts for the same obligation before scoring.

### C. Metrics and analysis

For labeled obligations, let TP, FP, TN, and FN denote true positives, false positives, true negatives, and false negatives. Report:

- **Precision:** TP / (TP + FP), the fraction of reported positives that are correct.
- **Recall:** TP / (TP + FN), the fraction of labeled vulnerabilities detected.
- **False-positive rate:** FP / (FP + TN), the fraction of non-vulnerable obligations reported as positive.
- **F1 score:** 2 × precision × recall / (precision + recall).
- **Unresolved rate:** unresolved obligations divided by all labeled obligations, reported for the hybrid method alongside its binary metrics.
- **Cost:** wall-clock time, number of test requests, and compute resources per application.
- **Context coverage:** the number and proportion of predefined policy-context combinations actually exercised, with coverage reported separately for identity, ownership, network route, and service trust.

Metrics with zero denominators should be reported as undefined, not as zero. Report counts as well as percentages, with confidence intervals and breakdowns by language and weakness. Because related obligations from one application are not independent, use application-level clustered bootstrap intervals and paired application-level comparisons. Predefine the primary metric and comparison before running the study, and treat small subgroup comparisons as exploratory. Report operational failures and timeouts separately.

### D. Reproducibility and ethics

Release prompts, source code, policy fixtures, labels, tool configurations, scripts, seeds, and anonymized logs where licensing and security permit. Capture container images or versioned build instructions. Deliberately vulnerable applications must be clearly labeled and run only in isolated test environments. No real credentials, personal information, or production endpoints should be used. If real-world vulnerabilities are discovered, follow coordinated disclosure before publishing exploit details.

## VII. Discussion and Limitations

The proposed framework could help reviewers connect a warning to a concrete policy violation, especially when a weakness depends on an identity or network boundary. It may also improve the usefulness of reports by separating unconfirmed paths from observed violations. These are hypotheses, not measured benefits.

Several limits are important. First, the system cannot test every possible input or deployment. Second, inaccurate policies and incomplete configuration can cause incorrect conclusions. Third, static models may miss dynamic language features, framework-specific behavior, and cross-service calls. Fourth, runtime instrumentation can alter behavior, while test doubles may not represent production. Fifth, labeling complex authorization rules requires expert judgment. Finally, generated benchmark applications may not reflect production systems, and any model-specific result may change as models and prompting practices change.

The term *verification* in this article means evidence-based checking against stated policies in a bounded environment. It does not imply a mathematical proof of security. A passing test or a contradicted candidate should never be interpreted as proof that the whole system is safe.

## VIII. Conclusion

LLM-synthesized microservices require security checks that account for both code and operating context. This article proposed a framework that uses static analysis to identify candidate weaknesses, explicit context and policy to guide dynamic tests, and runtime evidence to classify findings. It also presented an evaluation design using labeled obligations, matched contexts, baseline comparisons, and reproducible metrics. No experimental results are claimed. Future work should implement the framework, validate the ground-truth process, and measure whether the proposed combination provides a useful improvement over its individual components.

## References

[1] H. Pearce, B. Ahmad, B. Tan, B. Dolan-Gavitt, and R. Karri, “Asleep at the keyboard? Assessing the security of GitHub Copilot's code contributions,” in *Proc. 2022 IEEE Symp. Security and Privacy (SP)*, 2022, pp. 754–768. [Online]. Available: https://arxiv.org/abs/2108.09293

[2] N. Perry, M. Srivastava, D. Kumar, and D. Boneh, “Do users write more insecure code with AI assistants?,” in *Proc. 2023 ACM SIGSAC Conf. Computer and Communications Security*, 2023, doi: https://doi.org/10.1145/3576915.3623157.

[3] M. G. de Almeida and E. D. Canedo, “Authentication and authorization in microservices architecture: A systematic literature review,” *Applied Sciences*, vol. 12, no. 6, Art. no. 3023, 2022, doi: https://doi.org/10.3390/app12063023.

[4] S. Rawat, D. Ceara, L. Mounier, and M.-L. Potet, “Combining static and dynamic analysis for vulnerability detection,” arXiv:1305.3883, 2013. [Online]. Available: https://arxiv.org/abs/1305.3883

[5] P. Godefroid, N. Klarlund, and K. Sen, “DART: Directed automated random testing,” in *Proc. 2005 ACM SIGPLAN Conf. Programming Language Design and Implementation*, 2005, pp. 213–223, doi: https://doi.org/10.1145/1065010.1065036.

[6] Y. Fu, P. Liang, A. Tahir, Z. Li, M. Shahin, J. Yu, and J. Chen, “Security weaknesses of Copilot-generated code in GitHub projects: An empirical study,” arXiv:2310.02059, 2025. [Online]. Available: https://arxiv.org/abs/2310.02059

[7] GitHub, “About CodeQL.” [Online]. Available: https://docs.github.com/en/code-security/concepts/code-scanning/codeql/about-codeql. [Accessed: Nov. 17, 2026].
