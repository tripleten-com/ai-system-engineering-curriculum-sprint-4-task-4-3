# ModelProvider fidelity

The active adapter is an in-process deterministic emulation. From the Project 4 opening
checkpoint it imitates a hosted provider's wire shape rather than a parsed result: the worker
hands it a provider key at composition time, the request carries the reading, the handling note,
and the retrieved procedure excerpt, and the answer is one JSON document returned as raw text.
From Task 4.3 the worker passes that text through the supplied output guardrail before storing
anything from it. The emulator waits for the configured local latency and answers the same text
for the same request, every time.

The answer repeats what the request carried. A handling note comes back verbatim in the summary,
and so does the first sentence of the procedure excerpt. That is the behavior of a summarising
model given that text, and it is the behavior this Project's controls are measured against; it
is not a claim about any hosted model's output.

## The three supplied responses

Task 4.3 adds two supplied bad answers beside the default one, selected per request by the
reading's development-only `emulator_response` field (`poe scenario --response <name>` sets it,
and the worker copies it into the model request):

| Response | What the emulator returns | What it stands in for |
|---|---|---|
| `valid` (the default) | The JSON document the emulator has answered with since the opening checkpoint; it satisfies `schemas/exception-summary.schema.json` | A model that ignored the instruction planted in its input |
| `malformed` | The same document, stopped three fifths of the way through: not valid JSON | A provider that hit its output limit mid-answer |
| `manipulated` | Well-formed JSON that follows the instruction planted in the supplied procedure `playbook-thermal-excursion`: `next_step` set to a value outside the schema's list, and one field the schema does not name added | A model that did what text in its input told it to |

The manipulated response reads the planted sentence out of the procedure excerpt the request
carries and applies what it says; when the excerpt does not carry the sentence, the same two
deviations are applied from the emulator's constants, so the response is the same either way.
The selection is a property of this emulator and of nothing else: a hosted provider has no such
field, and nothing here shows how often, or in what shape, a hosted model would produce either
bad answer.

It proves the application contract, asynchronous composition, deterministic tests, and local
telemetry behavior, and it proves that the worker's guardrail and audit events behave the same
for a valid answer, a truncated one, and a manipulated one. It does not prove hosted-model
availability, output quality, token accounting, safety behavior, provider throttling, network
failure behavior, authentication against a provider, or cost. The key it is given is checked by
nothing at this checkpoint. No live endpoint or credential is used. The fixed delay is not a
performance measurement, capacity test, latency target, or availability claim.
