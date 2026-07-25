// False-positive regression fixture for D09's control-flow-flattening
// detector: an ordinary switch statement where every case returns
// directly (no goto back to a dispatcher) must not be flagged.
public class NormalSwitch {
    public String describe(int day) {
        switch (day) {
            case 1: return "Monday";
            case 2: return "Tuesday";
            case 3: return "Wednesday";
            case 4: return "Thursday";
            case 5: return "Friday";
            case 6: return "Saturday";
            case 7: return "Sunday";
            default: return "Unknown";
        }
    }
}
