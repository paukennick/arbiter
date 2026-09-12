# Setting up continuous training

## Why this file exists

Training makes the tool better over time. Each run plants known faults in real
code, checks whether the rules catch them, and writes down what it learned.

The catch is that the sandbox I work in is thrown away when the session ends.
Nothing survives. So every time we start, the tool knows exactly as much as it
did the first day.

A GitHub repository fixes that. It becomes the place the learning lives, so
each run picks up where the last one stopped.

## Why I could not do this part myself

My sandbox can reach GitHub, but only for repositories that have been
deliberately connected to it. Nothing is connected right now, and I have no way
to connect one or to create a repository. I checked:

- creating a repository — refused
- listing your repositories — refused
- reading any specific repository, including your own — refused

The refusal message is the same each time: this session is limited to
repositories that have been configured for it.

So this is the one step that has to come from you. It takes about two minutes.

## What you need to do

**1. Make an empty repository on GitHub.**

Call it `arbiter`. Private is fine. Do not let GitHub add a README or a
licence — it should be completely empty, or the first push will be rejected.

**2. Push the code I built.**

Unpack the archive I sent you, then from inside that folder:

```bash
git remote add origin https://github.com/<your-username>/arbiter.git
git push -u origin main
```

The folder is already a git repository with everything committed, so this is
the whole job.

**3. Connect the repository to Claude.**

In Claude, connect the new `arbiter` repository to this project or environment,
the same way you would connect any repository you want me to work on. That is
what tells my sandbox it is allowed to reach it.

**4. Tell me it is done.**

I will set up the recurring training runs. After that they happen on their own.

## What happens once it is connected

Each run:

1. downloads the practice repositories, if they are not already there
2. runs every rule against them and records what it found
3. plants known faults and checks the rules catch them
4. checks the tool never claims to have checked something it skipped
5. runs the test suite
6. commits the results back to the repository

Because step 6 writes to the repository, the next run starts from everything
the previous runs learned. That is the whole point.

To run a cycle by hand at any time:

```bash
./tools/train_cycle.sh           # about ten minutes
PUSH=1 ./tools/train_cycle.sh    # and save the results
```

## What training actually produces

A file called `.arbiter/knowledge.json`. It holds, for every rule:

- how many planted faults it was shown, and how many it caught
- how many look-alikes it was shown, and how many it correctly ignored
- how many real findings a person has reviewed and judged right or wrong

Those last numbers are kept separate from the first two on purpose. Faults I
generate come from a pattern I chose, so they tell you whether a rule works
mechanically. Only a person looking at a real finding tells you whether the
things it flags in real life are worth flagging. Mixing the two would let a
hundred thousand generated cases drown out ten real ones.

## One thing to know about the numbers

Running more trials does not make the tool more trustworthy past a point.
Twenty thousand faults generated from fifteen patterns is closer to fifteen
independent tests than to twenty thousand. What actually improves the evidence
is more kinds of fault and more kinds of code, not more repetitions.

That is why the practice set spans thirteen languages and five infrastructure
formats, and why every fault is planted into a real file rather than a
made-up one.
