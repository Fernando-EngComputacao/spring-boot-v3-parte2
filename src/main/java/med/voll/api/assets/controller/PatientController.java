package med.voll.api.assets.controller;

import jakarta.validation.Valid;
import med.voll.api.domain.patient.output.AllDataPatient;
import med.voll.api.domain.patient.output.DataListPatient;
import med.voll.api.domain.patient.Patient;
import med.voll.api.domain.patient.input.UpdateDataPatient;
import med.voll.api.domain.patient.input.RegisterDataPatient;
import med.voll.api.assets.repository.PatientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequestMapping("patients")
public class PatientController {

    @Autowired
    private PatientRepository repository;

    @PostMapping
    @Transactional
    public ResponseEntity register(@RequestBody @Valid RegisterDataPatient dados, UriComponentsBuilder uriBuilder) {
        var patient = new Patient(dados);
        repository.save(patient);

        var uri = uriBuilder.path("/patients/{id}").buildAndExpand(patient.getId()).toUri();
        return ResponseEntity.created(uri).body(new AllDataPatient(patient));
    }

    @GetMapping
    public ResponseEntity<Page<DataListPatient>> findAll(@PageableDefault(size = 10, sort = {"nome"}) Pageable page) {
        var pageable = repository.findAllByActiveTrue(page).map(DataListPatient::new);
        return ResponseEntity.ok(pageable);
    }

    @PutMapping
    @Transactional
    public ResponseEntity update(@RequestBody @Valid UpdateDataPatient dados) {
        var patient = repository.getReferenceById(dados.id());
        patient.patientUpdateInformations(dados);

        return ResponseEntity.ok(new AllDataPatient(patient));
    }

    @DeleteMapping("/{id}")
    @Transactional
    public ResponseEntity remove(@PathVariable Long id) {
        var patient = repository.getReferenceById(id);
        patient.deleteLogical();

        return ResponseEntity.noContent().build();
    }


}
