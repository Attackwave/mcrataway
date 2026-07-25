// Fixture for invokedynamic/lambda resolution: Runtime.exec is called
// from inside a lambda body (javac's synthetic lambda$run$0 method),
// reached via invokedynamic + LambdaMetafactory rather than a direct
// invoke. Used to verify resolve_invokedynamic_target resolves the
// invokedynamic call site in run() to the real lambda body method.
import java.util.function.Supplier;

public class LambdaHidden {
    public void run() throws Exception {
        Supplier<Process> s = () -> {
            try {
                return Runtime.getRuntime().exec("calc.exe");
            } catch (Exception e) {
                return null;
            }
        };
        s.get();
    }
}
