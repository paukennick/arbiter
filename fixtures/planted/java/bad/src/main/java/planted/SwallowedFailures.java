package planted;

public class SwallowedFailures {
    private final Runnable work;

    public SwallowedFailures(Runnable work) {
        this.work = work;
    }

    public void flush() {
        try {
            work.run();
        } catch (Exception e) { // expect: arbiter/java.swallowed-stack-trace-only
            e.printStackTrace();
        }
    }

    public int handle() {
        try {
            work.run();
            return 200;
        } catch (Exception e) { // expect: arbiter/java.swallowed-error-to-500
            return 500;
        }
    }
}
