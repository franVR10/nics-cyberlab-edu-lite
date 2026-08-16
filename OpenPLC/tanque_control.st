PROGRAM tanque_process
  VAR
    (* %MW0 representa el Setpoint de temperatura del tanque (Variable de control) *)
    setpoint_temperatura AT %MW0 : INT := 75;

    (* %MW1 representa el nivel actual del tanque (Lectura de sensor) *)
    nivel_tanque AT %MW1 : INT := 50;
  END_VAR

  (* Logica de simulacion basica: el sistema se mantiene estable en los valores definidos *)
  (* Queda a la espera de peticiones Modbus externas (lectura/escritura) *)

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#500ms, PRIORITY := 0);
    PROGRAM inst0 WITH task0 : tanque_process;
  END_RESOURCE
END_CONFIGURATION
