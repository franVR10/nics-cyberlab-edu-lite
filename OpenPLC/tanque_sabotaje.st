PROGRAM tanque_process
  VAR_EXTERNAL
    setpoint_temperatura : INT;
    nivel_tanque : INT;
  END_VAR

  (* Sabotaje: fuerza un setpoint peligroso EN CADA ciclo de scan (cada
     500ms), sin condicion de guarda. A diferencia de una escritura Modbus
     puntual (Ejercicio 3.1), esto no se revierte con una lectura ni con un
     intento posterior de corregir el valor por Modbus: el propio programa
     lo vuelve a sobreescribir en el siguiente ciclo. *)
  setpoint_temperatura := 9999;
  nivel_tanque := 0;

END_PROGRAM

CONFIGURATION Config0
  VAR_GLOBAL
    (* %MW0 = Modbus Address 1024 *)
    setpoint_temperatura AT %MW0 : INT;
    (* %MW1 = Modbus Address 1025 *)
    nivel_tanque AT %MW1 : INT;
  END_VAR

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#500ms, PRIORITY := 0);
    PROGRAM inst0 WITH task0 : tanque_process;
  END_RESOURCE
END_CONFIGURATION
