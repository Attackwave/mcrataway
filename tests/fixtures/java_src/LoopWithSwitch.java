// False-positive regression fixture for D09's control-flow-flattening
// detector: an ordinary for-loop containing a switch statement
// produces the same switch+multiple-goto shape as a flattened
// dispatcher (every break/continue in a loop-body switch compiles to
// a goto), but must NOT be flagged — the loop-bound comparison
// (arraylength + if_icmpge) immediately before the switch selector is
// what distinguishes it from a bare state-variable dispatch.
public class LoopWithSwitch {
    public void process(int[] items) {
        for (int i = 0; i < items.length; i++) {
            switch (items[i]) {
                case 1: System.out.println("one"); break;
                case 2: System.out.println("two"); break;
                case 3: continue;
                case 4: System.out.println("four"); break;
                case 5: System.out.println("five"); break;
                default: System.out.println("other"); break;
            }
            System.out.println("processed");
        }
    }
}
