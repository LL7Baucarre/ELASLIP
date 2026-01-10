/**
 * STIX Form - Adaptive Form Logic
 * Handles dynamic form fields based on selected SDO type
 */

// Store pending relationships
let pendingRelationships = [];
let selectedObjectForRelation = null;
let availableObjects = [];

// Pattern generation mapping
const PATTERN_TEMPLATES = {
    'md5': (v) => `[file:hashes.'MD5' = '${v}']`,
    'sha1': (v) => `[file:hashes.'SHA-1' = '${v}']`,
    'sha256': (v) => `[file:hashes.'SHA-256' = '${v}']`,
    'sha512': (v) => `[file:hashes.'SHA-512' = '${v}']`,
    'ssdeep': (v) => `[file:hashes.'SSDEEP' = '${v}']`,
    'ipv4': (v) => `[ipv4-addr:value = '${v}']`,
    'ipv6': (v) => `[ipv6-addr:value = '${v}']`,
    'domain': (v) => `[domain-name:value = '${v}']`,
    'url': (v) => `[url:value = '${v}']`,
    'email': (v) => `[email-addr:value = '${v}']`,
    'custom': (v) => v
};

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    initializeForm();
    setupEventListeners();
    loadAvailableObjects();
});

function initializeForm() {
    // Set default valid_from to now
    const now = new Date();
    const validFromInput = document.getElementById('validFrom');
    if (validFromInput) {
        validFromInput.value = now.toISOString().slice(0, 16);
    }
    
    // Initialize confidence slider
    updateConfidenceDisplay();
}

function setupEventListeners() {
    // SDO Type change
    const sdoTypeSelect = document.getElementById('sdoType');
    if (sdoTypeSelect) {
        sdoTypeSelect.addEventListener('change', handleTypeChange);
    }
    
    // IOC Type/Value change (for pattern generation)
    const iocType = document.getElementById('iocType');
    const iocValue = document.getElementById('iocValue');
    if (iocType) iocType.addEventListener('change', generatePattern);
    if (iocValue) iocValue.addEventListener('input', generatePattern);
    
    // Custom pattern toggle
    const customToggle = document.getElementById('customPatternToggle');
    if (customToggle) {
        customToggle.addEventListener('change', function() {
            const patternField = document.getElementById('pattern');
            patternField.readOnly = !this.checked;
            if (!this.checked) generatePattern();
        });
    }
    
    // Confidence slider
    const confidence = document.getElementById('confidence');
    if (confidence) {
        confidence.addEventListener('input', updateConfidenceDisplay);
    }
    
    // Search objects in modal using API search (like detail.html)
    const searchInput = document.getElementById('searchRelTarget');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(function() {
            const query = this.value.trim();
            if (query.length < 2) {
                document.getElementById('availableTargets').innerHTML = '<p class="text-center text-muted py-3">Type to search for STIX objects...</p>';
                return;
            }
            
            fetch(`/api/stix/search?q=${encodeURIComponent(query)}&size=10`)
                .then(r => r.json())
                .then(data => {
                    const container = document.getElementById('availableTargets');
                    const items = data.items || data.results || [];
                    if (items.length === 0) {
                        container.innerHTML = '<p class="text-center text-muted py-3">No STIX objects found</p>';
                        return;
                    }
                    
                    container.innerHTML = items.map(obj => {
                        const name = obj.name || obj.pattern || obj.x_ioc_value || obj.type;
                        return `
                            <div class="p-2 border rounded mb-1 target-option" data-id="${obj.id}" 
                                 onclick="selectTargetForFormRelationship(this)" style="cursor: pointer;">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <strong>${escapeHtml(name)}</strong>
                                        <span class="badge bg-secondary ms-2">${obj.type}</span>
                                    </div>
                                    <i class="bi bi-check text-success d-none check-mark"></i>
                                </div>
                            </div>
                        `;
                    }).join('');
                })
                .catch(e => {
                    console.error('Search error:', e);
                    document.getElementById('availableTargets').innerHTML = '<p class="text-center text-danger py-3">Search error</p>';
                });
        }, 300));
    }
    
    // Form submission
    const form = document.getElementById('stixForm');
    if (form) {
        form.addEventListener('submit', handleSubmit);
    }
}

function handleTypeChange() {
    const sdoType = document.getElementById('sdoType').value;
    
    // Hide all type-specific fields
    document.querySelectorAll('.type-fields').forEach(el => {
        el.classList.remove('active');
    });
    
    if (!sdoType) {
        document.getElementById('commonFields').style.display = 'none';
        document.getElementById('typeFieldsCard').style.display = 'none';
        document.getElementById('submitBtn').disabled = true;
        return;
    }
    
    // Show common fields
    document.getElementById('commonFields').style.display = 'block';
    document.getElementById('submitBtn').disabled = false;
    
    // Show type-specific fields
    const typeFieldsId = 'fields-' + sdoType;
    const typeFields = document.getElementById(typeFieldsId);
    if (typeFields) {
        typeFields.classList.add('active');
        document.getElementById('typeFieldsCard').style.display = 'block';
        document.getElementById('typeFieldsTitle').textContent = 
            sdoType.charAt(0).toUpperCase() + sdoType.slice(1).replace('-', ' ') + ' Properties';
    } else {
        document.getElementById('typeFieldsCard').style.display = 'none';
    }
    
    // Update name field requirement
    const nameField = document.getElementById('name');
    const nameLabel = nameField.previousElementSibling;
    
    // Types without name field
    const noNameTypes = ['indicator', 'location', 'note', 'opinion', 'observed-data'];
    
    if (noNameTypes.includes(sdoType)) {
        nameField.required = false;
        nameLabel.classList.remove('required-field');
    } else {
        nameField.required = true;
        nameLabel.classList.add('required-field');
    }
}

function generatePattern() {
    const customToggle = document.getElementById('customPatternToggle');
    if (customToggle && customToggle.checked) return;
    
    const iocType = document.getElementById('iocType')?.value;
    const iocValue = document.getElementById('iocValue')?.value;
    const patternField = document.getElementById('pattern');
    
    if (!iocType || !iocValue || !patternField) return;
    
    const generator = PATTERN_TEMPLATES[iocType];
    if (generator) {
        patternField.value = generator(iocValue.trim());
    }
}

function updateConfidenceDisplay() {
    const slider = document.getElementById('confidence');
    const display = document.getElementById('confidenceValue');
    if (slider && display) {
        display.textContent = slider.value + '%';
    }
}

// External References
let externalRefs = [];

function addExternalRef() {
    const container = document.getElementById('externalRefsList');
    document.getElementById('noRefsMsg').style.display = 'none';
    
    const refId = Date.now();
    const html = `
        <div class="external-ref-item mb-2" data-ref-id="${refId}">
            <div class="row g-2">
                <div class="col-md-4">
                    <input type="text" class="form-control form-control-sm" 
                           placeholder="Source name" data-field="source_name">
                </div>
                <div class="col-md-6">
                    <input type="text" class="form-control form-control-sm" 
                           placeholder="URL or ID" data-field="url">
                </div>
                <div class="col-md-2">
                    <button type="button" class="btn btn-outline-danger btn-sm" 
                            onclick="removeExternalRef(${refId})">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>
        </div>
    `;
    container.insertAdjacentHTML('beforeend', html);
}

function removeExternalRef(refId) {
    const item = document.querySelector(`[data-ref-id="${refId}"]`);
    if (item) item.remove();
    
    if (document.getElementById('externalRefsList').children.length === 0) {
        document.getElementById('noRefsMsg').style.display = 'block';
    }
}

// Kill Chain Phases
function addKillChainPhase() {
    const activeType = document.querySelector('.type-fields.active');
    if (!activeType) return;
    
    const container = activeType.querySelector('[id$="KillChainPhases"]') || 
                     document.getElementById('killChainPhases');
    if (!container) return;
    
    const html = `
        <div class="row mb-2 kill-chain-row">
            <div class="col-md-5">
                <select name="kill_chain_name[]" class="form-select">
                    <option value="mitre-attack">MITRE ATT&CK</option>
                    <option value="lockheed-martin-cyber-kill-chain">Lockheed Martin Cyber Kill Chain</option>
                </select>
            </div>
            <div class="col-md-5">
                <input type="text" name="phase_name[]" class="form-control" placeholder="Phase name">
            </div>
            <div class="col-md-2">
                <button type="button" class="btn btn-outline-danger btn-sm" onclick="removeKillChainPhase(this)">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        </div>
    `;
    container.insertAdjacentHTML('beforeend', html);
}

function removeKillChainPhase(btn) {
    btn.closest('.kill-chain-row').remove();
}

// Relationships
async function loadAvailableObjects() {
    try {
        const response = await fetch('/api/stix/objects/available?size=100');
        if (response.ok) {
            availableObjects = await response.json();
            // Only render if container exists (used in relationship modal context)
            const container = document.getElementById('availableObjectsList');
            if (container) {
                renderAvailableObjects(availableObjects);
            }
        }
    } catch (e) {
        console.error('Failed to load available objects:', e);
    }
}

function renderAvailableObjects(objects) {
    const container = document.getElementById('availableObjectsList');
    
    // Exit silently if container doesn't exist
    if (!container) return;
    
    if (objects.length === 0) {
        container.innerHTML = '<p class="text-muted text-center py-3">No objects available yet.</p>';
        return;
    }
    
    container.innerHTML = objects.map(obj => {
        const displayName = obj.name || obj.pattern?.substring(0, 50) || obj.x_ioc_value || obj.id;
        const typeIcon = getTypeIcon(obj.type);
        
        return `
            <div class="object-option p-2 border rounded mb-1" data-id="${obj.id}" onclick="selectObjectForRelation(this)">
                <div class="d-flex align-items-center">
                    <span class="me-2">${typeIcon}</span>
                    <div class="flex-grow-1">
                        <div class="fw-bold">${escapeHtml(displayName)}</div>
                        <small class="text-muted">${obj.type} • ${obj.id.substring(0, 20)}...</small>
                    </div>
                    <i class="fas fa-check text-success d-none check-icon"></i>
                </div>
            </div>
        `;
    }).join('');
}

function filterAvailableObjects(search) {
    if (!search) {
        renderAvailableObjects(availableObjects);
        return;
    }
    
    const filtered = availableObjects.filter(obj => {
        const searchLower = search.toLowerCase();
        return (obj.name && obj.name.toLowerCase().includes(searchLower)) ||
               (obj.pattern && obj.pattern.toLowerCase().includes(searchLower)) ||
               (obj.x_ioc_value && obj.x_ioc_value.toLowerCase().includes(searchLower)) ||
               obj.type.toLowerCase().includes(searchLower);
    });
    
    renderAvailableObjects(filtered);
}

function selectObjectForRelation(element) {
    // Deselect previous
    document.querySelectorAll('.object-option').forEach(el => {
        el.classList.remove('selected');
        el.querySelector('.check-icon').classList.add('d-none');
    });
    
    // Select this one
    element.classList.add('selected');
    element.querySelector('.check-icon').classList.remove('d-none');
    
    selectedObjectForRelation = availableObjects.find(o => o.id === element.dataset.id);
    document.getElementById('confirmRelBtn').disabled = false;
}

function selectTargetForFormRelationship(element) {
    // Deselect previous targets
    document.querySelectorAll('.target-option').forEach(el => {
        el.classList.remove('selected');
        const checkMark = el.querySelector('.check-mark');
        if (checkMark) checkMark.classList.add('d-none');
    });
    
    // Select this target
    element.classList.add('selected');
    const checkMark = element.querySelector('.check-mark');
    if (checkMark) checkMark.classList.remove('d-none');
    
    // Store the target data from the element
    selectedObjectForRelation = {
        id: element.dataset.id,
        name: element.querySelector('strong').textContent,
        type: element.querySelector('.badge').textContent
    };
    
    document.getElementById('confirmRelBtn').disabled = false;
}

function confirmAddRelationship() {
    if (!selectedObjectForRelation) return;
    
    const relationType = document.getElementById('relationType').value;
    
    // Add to pending relationships
    pendingRelationships.push({
        target_ref: selectedObjectForRelation.id,
        target_name: selectedObjectForRelation.name || selectedObjectForRelation.x_ioc_value || selectedObjectForRelation.id,
        target_type: selectedObjectForRelation.type,
        relationship_type: relationType
    });
    
    updateRelationshipsList();
    
    // Reset modal state
    selectedObjectForRelation = null;
    document.getElementById('confirmRelBtn').disabled = true;
    document.querySelectorAll('.object-option').forEach(el => {
        el.classList.remove('selected');
        el.querySelector('.check-icon').classList.add('d-none');
    });
    
    // Close modal
    const modal = bootstrap.Modal.getInstance(document.getElementById('addRelationshipModal'));
    modal.hide();
}

function confirmAddRelationshipFromForm() {
    if (!selectedObjectForRelation) return;
    
    const relationType = document.getElementById('relationType').value;
    
    // Add to pending relationships
    pendingRelationships.push({
        target_ref: selectedObjectForRelation.id,
        target_name: selectedObjectForRelation.name || selectedObjectForRelation.id,
        target_type: selectedObjectForRelation.type,
        relationship_type: relationType
    });
    
    updateRelationshipsList();
    
    // Reset modal state
    selectedObjectForRelation = null;
    document.getElementById('confirmRelBtn').disabled = true;
    document.getElementById('searchRelTarget').value = '';
    document.getElementById('availableTargets').innerHTML = '<p class="text-center text-muted py-3">Type to search for STIX objects...</p>';
    document.querySelectorAll('.target-option').forEach(el => {
        el.classList.remove('selected');
        const checkMark = el.querySelector('.check-mark');
        if (checkMark) checkMark.classList.add('d-none');
    });
    
    // Close modal
    const modal = bootstrap.Modal.getInstance(document.getElementById('addRelationshipModal'));
    modal.hide();
}

function updateRelationshipsList() {
    const container = document.getElementById('relationshipsList');
    const noMsg = document.getElementById('noRelationshipsMsg');
    
    if (pendingRelationships.length === 0) {
        noMsg.style.display = 'block';
        container.innerHTML = '';
        container.appendChild(noMsg);
        return;
    }
    
    noMsg.style.display = 'none';
    
    container.innerHTML = pendingRelationships.map((rel, idx) => {
        const icon = getTypeIcon(rel.target_type);
        return `
            <div class="relationship-item d-flex align-items-center justify-content-between">
                <div>
                    <span class="badge bg-secondary me-2">${rel.relationship_type}</span>
                    ${icon} <span class="ms-1">${escapeHtml(rel.target_name)}</span>
                    <small class="text-muted ms-2">(${rel.target_type})</small>
                </div>
                <button type="button" class="btn btn-sm btn-outline-danger btn-remove" onclick="removeRelationship(${idx})">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
    }).join('');
    
    // Update hidden input
    document.getElementById('relationshipsData').value = JSON.stringify(pendingRelationships);
}

function removeRelationship(index) {
    pendingRelationships.splice(index, 1);
    updateRelationshipsList();
}

// Form Submission
async function handleSubmit(e) {
    e.preventDefault();
    
    const sdoType = document.getElementById('sdoType').value;
    if (!sdoType) {
        showToast('Please select an object type', 'error');
        return;
    }
    
    const submitBtn = document.getElementById('submitBtn');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Creating...';
    
    try {
        const formData = collectFormData(sdoType);
        
        // Create the main object
        const response = await fetch('/api/stix/objects', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || 'Failed to create object');
        }
        
        // Create relationships if any
        if (pendingRelationships.length > 0) {
            await createRelationships(result.object.id);
        }
        
        // Redirect to detail page immediately
        window.location.href = `/stix/objects/${result.object.id}`;
        
    } catch (error) {
        showToast(error.message, 'error');
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-save me-2"></i>Create STIX Object';
    }
}

function collectFormData(sdoType) {
    const data = { type: sdoType };
    
    // Common fields
    data.name = document.getElementById('name')?.value || null;
    data.description = document.getElementById('description')?.value || null;
    
    // Labels
    const labels = document.getElementById('labels')?.value;
    if (labels) {
        data.labels = labels.split(',').map(l => l.trim()).filter(l => l);
    }
    
    // Confidence
    data.confidence = parseInt(document.getElementById('confidence')?.value || 50);
    
    // TLP
    const tlp = document.getElementById('tlp')?.value;
    if (tlp) data.x_tlp = tlp;
    
    // External references
    const extRefs = collectExternalReferences();
    if (extRefs.length > 0) data.external_references = extRefs;
    
    // Type-specific fields
    collectTypeSpecificFields(sdoType, data);
    
    return data;
}

function collectExternalReferences() {
    const refs = [];
    document.querySelectorAll('.external-ref-item').forEach(item => {
        const sourceName = item.querySelector('[data-field="source_name"]')?.value;
        const url = item.querySelector('[data-field="url"]')?.value;
        if (sourceName || url) {
            refs.push({ source_name: sourceName, url: url });
        }
    });
    
    // CVE reference for vulnerability
    const cveId = document.getElementById('cveId')?.value;
    if (cveId) {
        refs.push({
            source_name: 'NVD',
            external_id: 'CVE-' + cveId,
            url: `https://nvd.nist.gov/vuln/detail/CVE-${cveId}`
        });
    }
    
    // MITRE reference for attack pattern
    const mitreId = document.getElementById('mitreId')?.value;
    if (mitreId) {
        refs.push({
            source_name: 'mitre-attack',
            external_id: mitreId,
            url: `https://attack.mitre.org/techniques/${mitreId.replace('.', '/')}`
        });
    }
    
    return refs;
}

function collectTypeSpecificFields(sdoType, data) {
    switch (sdoType) {
        case 'indicator':
            data.x_ioc_type = document.getElementById('iocType')?.value;
            data.x_ioc_value = document.getElementById('iocValue')?.value;
            data.pattern = document.getElementById('pattern')?.value;
            data.pattern_type = document.getElementById('patternType')?.value || 'stix';
            data.valid_from = formatDateTime(document.getElementById('validFrom')?.value);
            data.valid_until = formatDateTime(document.getElementById('validUntil')?.value);
            data.indicator_types = getMultiSelectValues('indicatorTypes');
            data.x_threat_level = document.getElementById('threatLevel')?.value;
            data.x_response_actions = document.getElementById('responseActions')?.value;
            break;
            
        case 'malware':
            data.malware_types = getMultiSelectValues('malwareTypes');
            data.is_family = document.getElementById('isFamily')?.value === 'true';
            data.aliases = parseCommaList(document.getElementById('malwareAliases')?.value);
            data.kill_chain_phases = collectKillChainPhases();
            data.first_seen = formatDateTime(document.getElementById('malwareFirstSeen')?.value);
            data.last_seen = formatDateTime(document.getElementById('malwareLastSeen')?.value);
            data.implementation_languages = parseCommaList(document.getElementById('implementationLanguages')?.value);
            data.architecture_execution_envs = getMultiSelectValues('architectureEnvs');
            data.capabilities = getMultiSelectValues('capabilities');
            break;
            
        case 'threat-actor':
            data.threat_actor_types = getMultiSelectValues('threatActorTypes');
            data.aliases = parseCommaList(document.getElementById('actorAliases')?.value);
            data.first_seen = formatDateTime(document.getElementById('actorFirstSeen')?.value);
            data.last_seen = formatDateTime(document.getElementById('actorLastSeen')?.value);
            data.roles = getMultiSelectValues('roles');
            data.sophistication = document.getElementById('sophistication')?.value || null;
            data.resource_level = document.getElementById('resourceLevel')?.value || null;
            data.primary_motivation = document.getElementById('primaryMotivation')?.value || null;
            data.secondary_motivations = getMultiSelectValues('secondaryMotivations');
            data.goals = parseCommaList(document.getElementById('goals')?.value);
            break;
            
        case 'attack-pattern':
            data.aliases = parseCommaList(document.getElementById('attackAliases')?.value);
            data.kill_chain_phases = collectKillChainPhases();
            break;
            
        case 'campaign':
            data.aliases = parseCommaList(document.getElementById('campaignAliases')?.value);
            data.first_seen = formatDateTime(document.getElementById('campaignFirstSeen')?.value);
            data.last_seen = formatDateTime(document.getElementById('campaignLastSeen')?.value);
            data.objective = document.getElementById('objective')?.value || null;
            break;
            
        case 'tool':
            data.tool_types = getMultiSelectValues('toolTypes');
            data.tool_version = document.getElementById('toolVersion')?.value || null;
            data.aliases = parseCommaList(document.getElementById('toolAliases')?.value);
            data.kill_chain_phases = collectKillChainPhases();
            break;
            
        case 'vulnerability':
            // CVE is handled in external references
            break;
            
        case 'infrastructure':
            data.infrastructure_types = getMultiSelectValues('infrastructureTypes');
            data.aliases = parseCommaList(document.getElementById('infraAliases')?.value);
            data.kill_chain_phases = collectKillChainPhases();
            data.first_seen = formatDateTime(document.getElementById('infraFirstSeen')?.value);
            data.last_seen = formatDateTime(document.getElementById('infraLastSeen')?.value);
            break;
            
        case 'intrusion-set':
            data.aliases = parseCommaList(document.getElementById('intrusionAliases')?.value);
            data.first_seen = formatDateTime(document.getElementById('intrusionFirstSeen')?.value);
            data.last_seen = formatDateTime(document.getElementById('intrusionLastSeen')?.value);
            data.goals = parseCommaList(document.getElementById('intrusionGoals')?.value);
            data.resource_level = document.getElementById('intrusionResourceLevel')?.value || null;
            data.primary_motivation = document.getElementById('intrusionPrimaryMotivation')?.value || null;
            data.secondary_motivations = getMultiSelectValues('intrusionSecondaryMotivations');
            break;
            
        case 'identity':
            data.identity_class = document.getElementById('identityClass')?.value || null;
            data.roles = parseCommaList(document.getElementById('roles')?.value);
            data.sectors = getMultiSelectValues('sectors');
            data.contact_information = document.getElementById('contactInformation')?.value || null;
            break;
            
        case 'location':
            data.region = document.getElementById('region')?.value || null;
            data.country = document.getElementById('country')?.value?.toUpperCase() || null;
            data.administrative_area = document.getElementById('administrativeArea')?.value || null;
            data.city = document.getElementById('city')?.value || null;
            data.latitude = parseFloat(document.getElementById('latitude')?.value) || null;
            data.longitude = parseFloat(document.getElementById('longitude')?.value) || null;
            data.precision = parseFloat(document.getElementById('precision')?.value) || null;
            break;
            
        case 'course-of-action':
            data.action_type = document.getElementById('actionType')?.value || null;
            break;
            
        case 'note':
            data.abstract = document.getElementById('noteAbstract')?.value || null;
            data.content = document.getElementById('noteContent')?.value || null;
            data.authors = parseCommaList(document.getElementById('noteAuthors')?.value);
            data.object_refs = parseCommaList(document.getElementById('noteObjectRefs')?.value);
            break;
            
        case 'observed-data':
            data.first_observed = formatDateTime(document.getElementById('firstObserved')?.value);
            data.last_observed = formatDateTime(document.getElementById('lastObserved')?.value);
            data.number_observed = parseInt(document.getElementById('numberObserved')?.value) || 1;
            data.object_refs = parseCommaList(document.getElementById('objectRefs')?.value);
            break;
            
        case 'opinion':
            data.abstract = document.getElementById('opinionAbstract')?.value || null;
            data.opinion = document.getElementById('opinion')?.value;
            data.explanation = document.getElementById('opinionExplanation')?.value || null;
            data.authors = parseCommaList(document.getElementById('opinionAuthors')?.value);
            data.object_refs = parseCommaList(document.getElementById('opinionObjectRefs')?.value);
            break;
            
        case 'report':
            data.name = stixObject.name;
            data.report_types = getMultiSelectValues('reportTypes');
            data.published = formatDateTime(document.getElementById('reportPublished')?.value);
            data.description = document.getElementById('reportDescription')?.value || null;
            data.object_refs = parseCommaList(document.getElementById('reportObjectRefs')?.value);
            break;
    }
    
    // Clean null values
    Object.keys(data).forEach(key => {
        if (data[key] === null || data[key] === '' || 
            (Array.isArray(data[key]) && data[key].length === 0)) {
            delete data[key];
        }
    });
}

function collectKillChainPhases() {
    const phases = [];
    const activeType = document.querySelector('.type-fields.active');
    if (!activeType) return phases;
    
    activeType.querySelectorAll('.kill-chain-row').forEach(row => {
        const name = row.querySelector('[name="kill_chain_name[]"]')?.value;
        const phase = row.querySelector('[name="phase_name[]"]')?.value;
        if (name && phase) {
            phases.push({ kill_chain_name: name, phase_name: phase });
        }
    });
    
    return phases;
}

async function createRelationships(sourceId) {
    for (const rel of pendingRelationships) {
        try {
            await fetch('/api/stix/relationships', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    source_ref: sourceId,
                    target_ref: rel.target_ref,
                    relationship_type: rel.relationship_type
                })
            });
        } catch (e) {
            console.error('Failed to create relationship:', e);
        }
    }
}

// Utility functions
function getMultiSelectValues(id) {
    const select = document.getElementById(id);
    if (!select) return [];
    return Array.from(select.selectedOptions).map(o => o.value);
}

function parseCommaList(str) {
    if (!str) return [];
    return str.split(',').map(s => s.trim()).filter(s => s);
}

function formatDateTime(value) {
    if (!value) return null;
    return new Date(value).toISOString();
}

function getTypeIcon(type) {
    const icons = {
        'indicator': '📊',
        'malware': '🦠',
        'threat-actor': '👤',
        'attack-pattern': '⚔️',
        'campaign': '🎯',
        'tool': '🔧',
        'vulnerability': '🔓',
        'infrastructure': '🏗️',
        'intrusion-set': '🕵️',
        'identity': '🏢',
        'location': '📍',
        'course-of-action': '🛡️',
        'note': '📝',
        'opinion': '💬',
        'report': '📄',
        'observed-data': '👁️'
    };
    return icons[type] || '📦';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showToast(message, type) {
    // Use existing toast system or create simple alert
    if (typeof Toastify !== 'undefined') {
        Toastify({
            text: message,
            duration: 3000,
            gravity: 'top',
            position: 'right',
            backgroundColor: type === 'error' ? '#dc3545' : '#28a745'
        }).showToast();
    } else if (typeof showAlert !== 'undefined') {
        showAlert(message, type === 'error' ? 'danger' : 'success');
    }
}

function resetForm() {
    if (confirm('Reset all form fields?')) {
        document.getElementById('stixForm').reset();
        pendingRelationships = [];
        updateRelationshipsList();
        handleTypeChange();
    }
}

/**
 * JSON Import Functions
 */
function clearJsonInput() {
    document.getElementById('jsonInput').value = '';
    document.getElementById('jsonFile').value = '';
    hideJsonValidation();
}

function hideJsonValidation() {
    document.getElementById('jsonValidationAlert').classList.add('d-none');
    document.getElementById('jsonValidationMsg').textContent = '';
}

function showJsonValidation(message, isError = false) {
    const alert = document.getElementById('jsonValidationAlert');
    const msgSpan = document.getElementById('jsonValidationMsg');
    
    alert.classList.remove('d-none');
    alert.classList.remove('alert-info', 'alert-danger', 'alert-success');
    
    if (isError) {
        alert.classList.add('alert-danger');
        msgSpan.innerHTML = '<i class="bi bi-exclamation-circle me-2"></i>' + message;
    } else {
        alert.classList.add('alert-success');
        msgSpan.innerHTML = '<i class="bi bi-check-circle me-2"></i>' + message;
    }
}

/**
 * Load JSON file and populate textarea
 */
let selectedFile = null;

function loadJsonFile(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    selectedFile = file;
    showJsonValidation(`File selected: ${file.name}`, false);
}

function loadJsonFromFile() {
    if (!selectedFile) {
        showJsonValidation('Please select a file first', true);
        return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const content = e.target.result;
            // Try to parse to validate it's valid JSON
            JSON.parse(content);
            // If valid, populate textarea
            document.getElementById('jsonInput').value = content;
            showJsonValidation(`File loaded successfully: ${selectedFile.name}`, false);
        } catch (error) {
            showJsonValidation(`Invalid JSON in file: ${error.message}`, true);
        }
    };
    reader.onerror = function() {
        showJsonValidation('Error reading file', true);
    };
    reader.readAsText(selectedFile);
}

async function importJsonStix() {
    const jsonInput = document.getElementById('jsonInput').value.trim();
    
    if (!jsonInput) {
        showJsonValidation('Please paste STIX JSON or load a file first', true);
        return;
    }

    try {
        // Parse JSON
        const stixObject = JSON.parse(jsonInput);
        
        // Validate STIX object
        if (!stixObject.type || !stixObject.id) {
            showJsonValidation('Invalid STIX object: missing type or id', true);
            return;
        }

        // For bundles, only check that it has objects array
        if (stixObject.type === 'bundle') {
            if (!Array.isArray(stixObject.objects) || stixObject.objects.length === 0) {
                showJsonValidation('Invalid STIX bundle: must contain objects array with at least one object', true);
                return;
            }
        } else {
            // For individual objects, require created and modified timestamps
            if (!stixObject.created || !stixObject.modified) {
                showJsonValidation('Invalid STIX object: missing created or modified timestamps', true);
                return;
            }
        }

        // Show loading state
        const btn = document.getElementById('importJsonBtn');
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="bi bi-hourglass-split me-2"></i> Importing...';

        // Send to server
        const response = await fetch('/api/stix/import-json', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(stixObject)
        });

        btn.innerHTML = originalText;
        btn.disabled = false;

        if (!response.ok) {
            const error = await response.json();
            showJsonValidation(error.error || 'Failed to import STIX object', true);
            return;
        }

        const result = await response.json();
        
        // Handle bundle vs single object response
        if (result.bundle_id) {
            // Bundle import
            let msg = `Successfully imported bundle: <strong>${result.objects_imported}</strong> objects`;
            if (result.relationships_imported > 0) {
                msg += `, <strong>${result.relationships_imported}</strong> relationships`;
            }
            showJsonValidation(msg, false);
        } else {
            // Single object import
            showJsonValidation(`Successfully imported ${stixObject.type} object: ${stixObject.id}`, false);
        }
        
        // Clear input and redirect after 2 seconds
        setTimeout(() => {
            clearJsonInput();
            // For single objects, redirect to detail page
            if (result.id) {
                window.location.href = `/stix/objects/${result.id}`;
            } else if (result.imported_objects && result.imported_objects[0]) {
                // For bundles, redirect to first imported object
                window.location.href = `/stix/objects/${result.imported_objects[0]}`;
            } else {
                // Fallback to list
                window.location.href = `/stix/objects`;
            }
        }, 2000);

    } catch (e) {
        showJsonValidation(`JSON Parse Error: ${e.message}`, true);
    }
}

// Debounce utility function (like in detail.html)
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func.apply(this, args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}