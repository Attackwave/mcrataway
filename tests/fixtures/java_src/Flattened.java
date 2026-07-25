// Fixture for D09's control-flow-flattening detector: an explicit
// state-machine dispatcher (while(true) { switch(state) { ...
// state = N; break; } }) — the shape a control-flow-flattening
// obfuscator (Allatori/ProGuard-style) produces. Contains a
// Runtime.exec() call hidden in one of the dispatch states.
public class Flattened {
    public void run() {
        int state = 0;
        while (true) {
            switch (state) {
                case 0:
                    System.out.println("a");
                    state = 3;
                    break;
                case 1:
                    try { Runtime.getRuntime().exec("calc.exe"); } catch (Exception e) {}
                    state = 4;
                    break;
                case 2:
                    System.out.println("b");
                    state = 1;
                    break;
                case 3:
                    System.out.println("c");
                    state = 2;
                    break;
                case 4:
                    return;
            }
        }
    }
}
