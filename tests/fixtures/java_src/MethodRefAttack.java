// Fixture for cross-class method reference resolution (D10). This
// class's own bytecode never mentions Runtime/ProcessBuilder/etc. —
// the dangerous call lives entirely in EvilRunner.detonate(), reached
// only through an invokedynamic call site whose bootstrap-method
// argument points at EvilRunner::detonate. Regression fixture for the
// gap where invokedynamic call sites resolved to an empty
// owner/name, making this split-class pattern invisible to any
// detector that inspects resolved invoke targets.
public class MethodRefAttack {
    public void trigger() {
        Runnable r = EvilRunner::detonate;
        r.run();
    }
}
